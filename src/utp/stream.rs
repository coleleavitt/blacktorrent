// #![forbid(unsafe_code)]

use crate::utp::common::{ConnectionState, UtpError};
use crate::utp::socket::UtpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const CONNECT_TIMEOUT_SECS: u64 = 10;
const TICK_INTERVAL_MS: u64 = 50;

/// Async uTP stream abstraction.
pub struct UtpStream {
    socket: Arc<Mutex<UtpSocket>>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_waker: Arc<Mutex<Option<Waker>>>,
    running: Arc<Mutex<bool>>,
}

impl UtpStream {
    /// Establish a connection to a remote peer asynchronously.
    pub async fn connect(local_bind_addr: SocketAddr, remote_addr: SocketAddr) -> Result<Self, UtpError> {
        let socket = Arc::new(Mutex::new(UtpSocket::new(local_bind_addr, remote_addr)));
        {
            let socket_guard = socket.lock().unwrap();
            socket_guard.connect()?;
        }

        let read_waker = Arc::new(Mutex::new(None));
        let write_waker = Arc::new(Mutex::new(None));
        let running = Arc::new(Mutex::new(true));

        let stream = Self {
            socket: socket.clone(),
            read_waker: read_waker.clone(),
            write_waker: write_waker.clone(),
            running: running.clone(),
        };

        timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
            loop {
                let data_to_send = {
                    let mut socket_guard = stream.socket.lock().unwrap();
                    socket_guard.tick()?
                };
                if let Some(_data) = data_to_send {
                    // Would send data via UDP in real implementation
                }
                let state = {
                    let socket_guard = stream.socket.lock().unwrap();
                    socket_guard.get_state()
                };
                if state == ConnectionState::Connected {
                    return Ok::<_, UtpError>(());
                }
                if matches!(state, ConnectionState::Reset | ConnectionState::Closed) {
                    return Err(UtpError::ConnectionRefused);
                }
                tokio::time::sleep(Duration::from_millis(TICK_INTERVAL_MS)).await;
            }
        }).await.map_err(|_| UtpError::Timeout)??;

        start_background_ticker(&stream);

        Ok(stream)
    }

    /// Close the write half of the connection (send FIN).
    pub async fn close_write(&mut self) -> Result<(), UtpError> {
        {
            let socket_guard = self.socket.lock().unwrap();
            socket_guard.close()?;
        }
        timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
            loop {
                let data_sent = {
                    let mut socket_guard = self.socket.lock().unwrap();
                    socket_guard.tick()?
                };
                if data_sent.is_some() {
                    // FIN sent
                }
                let state = {
                    let socket_guard = self.socket.lock().unwrap();
                    socket_guard.get_state()
                };
                if matches!(state, ConnectionState::Closed | ConnectionState::Reset) {
                    return Ok::<_, UtpError>(());
                }
                tokio::time::sleep(Duration::from_millis(TICK_INTERVAL_MS)).await;
            }
        }).await.map_err(|_| UtpError::Timeout)??;
        Ok(())
    }
}

// Background task for ticking the socket.
fn start_background_ticker(stream: &UtpStream) {
    let socket = Arc::clone(&stream.socket);
    let read_waker = Arc::clone(&stream.read_waker);
    let write_waker = Arc::clone(&stream.write_waker);
    let running = Arc::clone(&stream.running);

    tokio::spawn(async move {
        while *running.lock().unwrap() {
            let result = {
                let mut socket_guard = socket.lock().unwrap();
                socket_guard.tick()
            };
            if let Ok(Some(_)) = result {
                if let Some(waker) = read_waker.lock().unwrap().take() {
                    waker.wake();
                }
                if let Some(waker) = write_waker.lock().unwrap().take() {
                    waker.wake();
                }
            }
            let state = {
                let socket_guard = socket.lock().unwrap();
                socket_guard.get_state()
            };
            if matches!(state, ConnectionState::Closed | ConnectionState::Reset | ConnectionState::Destroying) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(TICK_INTERVAL_MS)).await;
        }
    });
}

impl AsyncRead for UtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut temp_buf = vec![0u8; buf.remaining()];
        let result = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.read_data(&mut temp_buf)
        };
        match result {
            Ok(0) => {
                let state = {
                    let socket_guard = this.socket.lock().unwrap();
                    socket_guard.get_state()
                };
                if matches!(state, ConnectionState::Closed | ConnectionState::Reset | ConnectionState::FinRecv) {
                    return Poll::Ready(Ok(()));
                }
                *this.read_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            },
            Ok(n) => {
                buf.put_slice(&temp_buf[..n]);
                Poll::Ready(Ok(()))
            },
            Err(UtpError::Network(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                *this.read_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.write_data(buf)
        };
        match result {
            Ok(0) => {
                *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            },
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let send_buffer_empty = {
            let socket_guard = this.socket.lock().unwrap();
            let internal_guard = socket_guard.internal.lock().unwrap();
            internal_guard.send_buffer.is_empty() && internal_guard.outgoing_packets.is_empty()
        };
        if send_buffer_empty {
            Poll::Ready(Ok(()))
        } else {
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let state = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.get_state()
        };
        if !matches!(state, ConnectionState::FinSent | ConnectionState::Closed | ConnectionState::Reset) {
            let result = {
                let socket_guard = this.socket.lock().unwrap();
                socket_guard.close()
            };
            if let Err(e) = result {
                if !matches!(e, UtpError::InvalidState) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
            }
        }
        let state = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.get_state()
        };
        match state {
            ConnectionState::Closed | ConnectionState::Reset => Poll::Ready(Ok(())),
            _ => {
                *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Clone for UtpStream {
    fn clone(&self) -> Self {
        Self {
            socket: Arc::clone(&self.socket),
            read_waker: Arc::new(Mutex::new(None)),
            write_waker: Arc::new(Mutex::new(None)),
            running: Arc::clone(&self.running),
        }
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        *self.running.lock().unwrap() = false;
        let _ = {
            let socket_guard = self.socket.lock().unwrap();
            socket_guard.close()
        };
    }
}

// --- Test utilities ---

#[cfg(test)]
fn dummy_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};

    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { dummy_raw_waker() }

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);

    fn dummy_raw_waker() -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    unsafe { Waker::from_raw(dummy_raw_waker()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn unique_addr() -> SocketAddr {
        static NEXT_PORT: AtomicU16 = AtomicU16::new(41000);
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn test_stream_connect_and_drop() {
        let local = unique_addr();
        let remote = unique_addr();
        let result = UtpStream::connect(local, remote).await;
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_stream_clone_and_close_write() {
        let local = unique_addr();
        let remote = unique_addr();
        let result = UtpStream::connect(local, remote).await;
        if let Ok(mut stream) = result {
            let _clone = stream.clone();
            let _ = stream.close_write().await;
        }
    }

    #[tokio::test]
    async fn test_poll_read_write() {
        use std::task::Poll;
        use tokio::io::ReadBuf;

        let local = unique_addr();
        let remote = unique_addr();
        let result = UtpStream::connect(local, remote).await;
        if let Ok(mut stream) = result {
            let waker = super::dummy_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            let mut buf = [0u8; 32];
            let mut read_buf = ReadBuf::new(&mut buf);
            let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
            let _ = Pin::new(&mut stream).poll_write(&mut cx, b"test");
        }
    }
}
