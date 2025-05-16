// utp/stream.rs

use crate::utp::common::{ConnectionState, UtpError};
use crate::utp::socket::UtpSocket;
use std::net::SocketAddr;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const CONNECT_TIMEOUT_SECS: u64 = 10;
const TICK_INTERVAL_MS: u64 = 50;

/// A uTP stream between a local and a remote socket.
/// This provides an async interface to the uTP protocol.
pub struct UtpStream {
    socket: Arc<Mutex<UtpSocket>>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    write_waker: Arc<Mutex<Option<Waker>>>,
    running: Arc<Mutex<bool>>,
}

impl UtpStream {
    /// Connects to a remote uTP peer asynchronously.
    pub async fn connect(local_bind_addr: SocketAddr, remote_addr: SocketAddr) -> Result<Self, UtpError> {
        // Create the socket and initiate connection
        let socket = Arc::new(Mutex::new(UtpSocket::new(local_bind_addr, remote_addr)));

        // Start connection
        {
            let socket_guard = socket.lock().unwrap();
            socket_guard.connect()?;
        }

        let read_waker = Arc::new(Mutex::new(None));
        let write_waker = Arc::new(Mutex::new(None));
        let running = Arc::new(Mutex::new(true));

        let stream = Self {
            socket,
            read_waker,
            write_waker,
            running,
        };

        // Wait for the connection to be established with a timeout
        timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
            loop {
                // Process tick to move the connection state machine
                let data_to_send = {
                    let mut socket_guard = stream.socket.lock().unwrap();
                    socket_guard.tick()?
                };

                if let Some(data) = data_to_send {
                    // In a real implementation, this would send the data via UDP
                    println!("Would send {} bytes to {}", data.len(), remote_addr);
                }

                // Check if we're connected
                let state = {
                    let socket_guard = stream.socket.lock().unwrap();
                    socket_guard.get_state()
                };

                if state == ConnectionState::Connected {
                    return Ok::<_, UtpError>(());
                }

                // Check for connection failure
                if matches!(state, ConnectionState::Reset | ConnectionState::Closed) {
                    return Err(UtpError::ConnectionRefused);
                }

                tokio::time::sleep(Duration::from_millis(TICK_INTERVAL_MS)).await;
            }
        }).await.map_err(|_| UtpError::Timeout)??;

        // Start background task for socket ticking
        start_background_ticker(&stream);

        Ok(stream)
    }

    /// Closes the write half of the connection by sending a FIN packet.
    pub async fn close_write(&mut self) -> Result<(), UtpError> {
        {
            let socket_guard = self.socket.lock().unwrap();
            socket_guard.close()?;
        }

        // Wait for the FIN to be acknowledged or the connection to close
        timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
            loop {
                let data_sent = {
                    let mut socket_guard = self.socket.lock().unwrap();
                    socket_guard.tick()?
                };

                if data_sent.is_some() {
                    // Data was processed (FIN sent)
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

// Starts a background task that processes socket events
fn start_background_ticker(stream: &UtpStream) {
    let socket = Arc::clone(&stream.socket);
    let read_waker = Arc::clone(&stream.read_waker);
    let write_waker = Arc::clone(&stream.write_waker);
    let running = Arc::clone(&stream.running);

    tokio::spawn(async move {
        while *running.lock().unwrap() {
            // Process socket tick
            let result = {
                let mut socket_guard = socket.lock().unwrap();
                socket_guard.tick()
            };

            if let Ok(Some(_)) = result {
                // Wake up waiting readers/writers
                if let Some(waker) = read_waker.lock().unwrap().take() {
                    waker.wake();
                }
                if let Some(waker) = write_waker.lock().unwrap().take() {
                    waker.wake();
                }
            }

            // Check if connection is closed
            let state = {
                let socket_guard = socket.lock().unwrap();
                socket_guard.get_state()
            };

            if matches!(state, 
                ConnectionState::Closed | ConnectionState::Reset | ConnectionState::Destroying) {
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
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut temp_buf = vec![0u8; buf.remaining()];

        // Try to read data
        let result = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.read_data(&mut temp_buf)
        };

        match result {
            Ok(0) => {
                // Check if we've reached EOF
                let state = {
                    let socket_guard = this.socket.lock().unwrap();
                    socket_guard.get_state()
                };

                if matches!(state, 
                    ConnectionState::Closed | ConnectionState::Reset | ConnectionState::FinRecv) {
                    return Poll::Ready(Ok(()));
                }

                // No data yet, store waker for notification
                *this.read_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            },
            Ok(n) => {
                // Copy data into the output buffer
                buf.put_slice(&temp_buf[..n]);
                Poll::Ready(Ok(()))
            },
            Err(UtpError::Network(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available yet
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

        // Try to write data
        let result = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.write_data(buf)
        };

        match result {
            Ok(0) => {
                // Socket buffer is full, register for notification
                *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            },
            Ok(n) => {
                // Successfully wrote some data
                Poll::Ready(Ok(n))
            },
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if the send buffer is empty
        let send_buffer_empty = {
            let socket_guard = this.socket.lock().unwrap();
            let internal_guard = socket_guard.internal.lock().unwrap();
            internal_guard.send_buffer.is_empty() && internal_guard.outgoing_packets.is_empty()
        };

        if send_buffer_empty {
            // All data has been processed and sent
            Poll::Ready(Ok(()))
        } else {
            // Still have data to send
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Send FIN packet if needed
        let state = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.get_state()
        };

        if !matches!(state, 
            ConnectionState::FinSent | ConnectionState::Closed | ConnectionState::Reset) {
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

        // Check if connection is fully closed
        let state = {
            let socket_guard = this.socket.lock().unwrap();
            socket_guard.get_state()
        };

        match state {
            ConnectionState::Closed | ConnectionState::Reset => {
                Poll::Ready(Ok(()))
            },
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
        // Signal background task to stop
        *self.running.lock().unwrap() = false;

        // Attempt to close the connection gracefully
        let _ = {
            let socket_guard = self.socket.lock().unwrap();
            socket_guard.close()
        };
    }
}
