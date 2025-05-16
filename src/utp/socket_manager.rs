#![allow(dead_code)]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{timeout, Duration};

use crate::utp::common::UtpError;
use crate::utp::dispatcher::{UtpDispatcher, DispatcherCommand};
use crate::utp::socket::UtpSocket;

/// Maximum operation time in milliseconds
const OPERATION_TIMEOUT_MS: u64 = 100;
/// Maximum pending connections, statically bounded
const MAX_PENDING_CONNECTIONS: usize = 16;
/// Triple redundancy array size for fault tolerance
const TMR_SIZE: usize = 3;

pub struct UtpSocketManager {
    dispatcher: Mutex<UtpDispatcher>,
    command_tx: mpsc::Sender<DispatcherCommand>,
    local_addr: [SocketAddr; TMR_SIZE], // Triple redundancy for SEU protection
    active: AtomicBool,
}

impl UtpSocketManager {
    pub async fn new(bind_addr: SocketAddr) -> Result<Self, UtpError> {
        let dispatcher = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            UtpDispatcher::new(bind_addr)
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Dispatcher creation timed out".into())),
        };

        let command_tx = dispatcher.get_command_sender();

        let manager = Self {
            dispatcher: Mutex::new(dispatcher),
            command_tx: command_tx.clone(),
            local_addr: [bind_addr, bind_addr, bind_addr], // Triple redundancy
            active: AtomicBool::new(true),
        };

        let bind_addr_clone = bind_addr;
        let task_command_tx = command_tx;

        tokio::spawn(async move {
            match UtpDispatcher::new(bind_addr_clone).await {
                Ok(mut task_dispatcher) => {
                    task_dispatcher.run().await;
                },
                Err(e) => {
                    eprintln!("CRITICAL ERROR: Failed to create task dispatcher: {:?}", e);
                }
            }
            loop {
                if task_command_tx.send(DispatcherCommand::Heartbeat).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(manager)
    }

    pub async fn create_connection(&self, remote_addr: SocketAddr) -> Result<Mutex<UtpSocket>, UtpError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        let local_addr = self.get_local_addr()?;
        let socket = UtpSocket::new(local_addr, remote_addr);
        let conn_id = socket.connection_id();
        let (tx, rx) = oneshot::channel();

        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS / 2),
            self.command_tx.send(
                DispatcherCommand::RegisterSocketInfo(remote_addr, conn_id, tx)
            )
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to register socket".into()))?,
            Err(_) => return Err(UtpError::Internal("Register socket command timed out".into())),
        };

        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS / 2),
            rx
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to confirm socket registration".into()))?,
            Err(_) => return Err(UtpError::Internal("Registration confirmation timed out".into())),
        };

        Ok(Mutex::new(socket))
    }

    pub fn get_command_sender(&self) -> mpsc::Sender<DispatcherCommand> {
        self.command_tx.clone()
    }

    pub async fn listen(&self) -> Result<UtpListener, UtpError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        let local_addr = self.get_local_addr()?;
        let (listener_tx, listener_rx) = mpsc::channel(MAX_PENDING_CONNECTIONS);

        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            async {
                let dispatcher = self.dispatcher.lock().await;
                dispatcher.register_listener(local_addr, listener_tx).await?;
                Ok::<_, UtpError>(())
            }
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Listener registration timed out".into())),
        };

        Ok(UtpListener {
            local_addr: [local_addr, local_addr, local_addr],
            dispatcher_tx: self.command_tx.clone(),
            incoming: listener_rx,
            active: AtomicBool::new(true),
        })
    }

    pub async fn shutdown(&self) -> Result<(), UtpError> {
        self.active.store(false, Ordering::Release);

        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            self.command_tx.send(DispatcherCommand::Shutdown)
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to send shutdown command".into()))?,
            Err(_) => return Err(UtpError::Internal("Shutdown command timed out".into())),
        };

        Ok(())
    }

    fn get_local_addr(&self) -> Result<SocketAddr, UtpError> {
        if self.local_addr[0] == self.local_addr[1] {
            return Ok(self.local_addr[0]);
        }
        if self.local_addr[0] == self.local_addr[2] {
            return Ok(self.local_addr[0]);
        }
        if self.local_addr[1] == self.local_addr[2] {
            return Ok(self.local_addr[1]);
        }
        Err(UtpError::Internal("Local address data corruption detected".into()))
    }
}

pub struct UtpListener {
    local_addr: [SocketAddr; TMR_SIZE],
    dispatcher_tx: mpsc::Sender<DispatcherCommand>,
    incoming: mpsc::Receiver<Mutex<UtpSocket>>,
    active: AtomicBool,
}

impl UtpListener {
    pub async fn accept(&mut self) -> Result<(UtpSocket, SocketAddr), UtpError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Listener is inactive".into()));
        }

        let socket_mutex = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS * 5),
            self.incoming.recv()
        ).await {
            Ok(Some(socket)) => socket,
            Ok(None) => return Err(UtpError::Internal("Listener channel closed".into())),
            Err(_) => return Err(UtpError::Internal("Accept operation timed out".into())),
        };

        let (remote_addr, socket_info) = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            async {
                let socket_guard = socket_mutex.lock().await;
                let remote_addr = socket_guard.remote_address();
                let conn_id = socket_guard.connection_id();
                Ok::<_, UtpError>((remote_addr, conn_id))
            }
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Socket attribute extraction timed out".into())),
        };

        let local_addr = self.get_local_addr()?;
        let socket = UtpSocket::new(local_addr, remote_addr);

        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            socket.initialize_from_connection(socket_info)
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Socket initialization timed out".into())),
        };

        Ok((socket, remote_addr))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.get_local_addr().unwrap_or_else(|_| {
            log_error("Critical error: All local_addr copies corrupted");
            self.local_addr[0]
        })
    }

    fn get_local_addr(&self) -> Result<SocketAddr, UtpError> {
        if self.local_addr[0] == self.local_addr[1] {
            return Ok(self.local_addr[0]);
        }
        if self.local_addr[0] == self.local_addr[2] {
            return Ok(self.local_addr[0]);
        }
        if self.local_addr[1] == self.local_addr[2] {
            return Ok(self.local_addr[1]);
        }
        Err(UtpError::Internal("Local address data corruption detected".into()))
    }
}

impl Drop for UtpListener {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        if let Ok(addr) = self.get_local_addr() {
            let tx = self.dispatcher_tx.clone();
            let _ = tx.try_send(DispatcherCommand::UnregisterListener(addr));
        }
    }
}

async fn is_shutdown_requested(tx: &mpsc::Sender<DispatcherCommand>) -> bool {
    match tx.send(DispatcherCommand::Heartbeat).await {
        Ok(_) => false,
        Err(_) => true,
    }
}

fn log_error(message: &str) {
    eprintln!("CRITICAL ERROR: {}", message);
    #[cfg(feature = "logging")]
    {
        crate::log::critical(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utp::dispatcher::UtpDispatcher;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn unique_addr() -> SocketAddr {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT_PORT: AtomicU16 = AtomicU16::new(40000);
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn test_manager_new_and_shutdown() {
        let addr = unique_addr();
        let manager = UtpSocketManager::new(addr).await.expect("Failed to create manager");
        assert!(manager.active.load(Ordering::Acquire));
        manager.shutdown().await.expect("Shutdown failed");
        assert!(!manager.active.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_create_connection() {
        let addr = unique_addr();
        let manager = UtpSocketManager::new(addr).await.expect("Failed to create manager");
        let remote = unique_addr();
        let socket_mutex = manager.create_connection(remote).await.expect("Failed to create connection");
        let socket = socket_mutex.lock().await;
        assert_eq!(socket.remote_address(), remote);
    }

    #[tokio::test]
    async fn test_listen_and_accept_mock() {
        let addr = unique_addr();
        let manager = UtpSocketManager::new(addr).await.expect("Failed to create manager");
        let mut listener = manager.listen().await.expect("Failed to listen");
        // We can't actually connect a peer in a unit test without a running dispatcher,
        // but we can check that the listener is active and local_addr is correct.
        assert!(listener.active.load(Ordering::Acquire));
        assert_eq!(listener.local_addr(), addr);
    }

    #[tokio::test]
    async fn test_triple_redundancy_addr() {
        let addr = unique_addr();
        let manager = UtpSocketManager::new(addr).await.expect("Failed to create manager");
        assert_eq!(manager.get_local_addr().unwrap(), addr);
    }
}
