use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout, Duration};

use crate::utp::common::UtpError;
use crate::utp::dispatcher::{UtpDispatcher, DispatcherCommand};
use crate::utp::socket::UtpSocket;

const OPERATION_TIMEOUT_MS: u64 = 100;
const MAX_PENDING_CONNECTIONS: usize = 16;
const TMR_SIZE: usize = 3;

pub struct UtpSocketManager {
    dispatcher_tx: mpsc::Sender<DispatcherCommand>,
    local_addr: [SocketAddr; TMR_SIZE],
    active: AtomicBool,
}

impl UtpSocketManager {
    pub async fn new(bind_addr: SocketAddr) -> Result<Self, UtpError> {
        // Create dispatcher with timeout protection
        let dispatcher_result = timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            UtpDispatcher::new(bind_addr)
        ).await;

        let mut dispatcher = match dispatcher_result {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Dispatcher creation timed out".into())),
        };

        // Get command sender before moving dispatcher
        let command_tx = dispatcher.get_command_sender();
        let heartbeat_tx = command_tx.clone();

        // Spawn dispatcher in its own task using move semantics
        tokio::spawn(async move {
            dispatcher.run().await;
        });

        // Spawn heartbeat task with its own command sender clone
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if heartbeat_tx.send(DispatcherCommand::Heartbeat).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            dispatcher_tx: command_tx,
            local_addr: [bind_addr; TMR_SIZE],
            active: AtomicBool::new(true),
        })
    }

    pub async fn create_connection(&self, remote_addr: SocketAddr) -> Result<UtpSocket, UtpError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        let local_addr = self.get_local_addr()?;
        let socket = UtpSocket::new(local_addr, remote_addr);
        let conn_id = socket.connection_id();

        let (tx, rx) = oneshot::channel();

        // Register socket with dispatcher
        self.dispatcher_tx.send(
            DispatcherCommand::RegisterSocketInfo(remote_addr, conn_id, tx)
        ).await
            .map_err(|_| UtpError::Internal("Failed to register socket".into()))?;

        // Wait for confirmation
        rx.await
            .map_err(|_| UtpError::Internal("Failed to confirm socket registration".into()))?;

        Ok(socket)
    }

    pub async fn listen(&self) -> Result<UtpListener, UtpError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        let local_addr = self.get_local_addr()?;

        // Channel for incoming connections: must match dispatcher (Mutex<UtpSocket>)
        let (listener_tx, listener_rx) = mpsc::channel::<Mutex<UtpSocket>>(MAX_PENDING_CONNECTIONS);

        // Register listener with dispatcher
        let register_cmd = DispatcherCommand::RegisterListener(local_addr, listener_tx);
        self.dispatcher_tx.send(register_cmd).await
            .map_err(|_| UtpError::Internal("Failed to register listener".into()))?;

        Ok(UtpListener {
            local_addr: [local_addr; TMR_SIZE],
            dispatcher_tx: self.dispatcher_tx.clone(),
            incoming: listener_rx,
            active: AtomicBool::new(true),
        })
    }

    pub async fn shutdown(&self) -> Result<(), UtpError> {
        self.active.store(false, Ordering::Release);
        self.dispatcher_tx.send(DispatcherCommand::Shutdown).await
            .map_err(|_| UtpError::Internal("Failed to send shutdown command".into()))
    }

    fn get_local_addr(&self) -> Result<SocketAddr, UtpError> {
        // Majority voting for fault tolerance
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

        // Use timeout to prevent blocking indefinitely
        match timeout(Duration::from_millis(OPERATION_TIMEOUT_MS * 5), self.incoming.recv()).await {
            Ok(Some(socket_mutex)) => {
                let socket = socket_mutex.into_inner();
                let remote = socket.remote_address();
                Ok((socket, remote))
            }
            Ok(None) => Err(UtpError::Internal("Listener channel closed".into())),
            Err(_) => Err(UtpError::Internal("Accept operation timed out".into())),
        }
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
            let _ = self.dispatcher_tx.try_send(DispatcherCommand::UnregisterListener(addr));
        }
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

    /// Generates a unique socket address for testing
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
        let socket = manager.create_connection(remote).await.expect("Failed to create connection");
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
