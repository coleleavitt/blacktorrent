// utp/socket_manager.rs

#![allow(dead_code)]
#![forbid(unsafe_code)]

use std::net::SocketAddr;
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
/// Maximum retries for critical operations
const MAX_RETRIES: usize = 3;
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
        // Apply timeout for deterministic execution bounds
        let dispatcher = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            UtpDispatcher::new(bind_addr)
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Dispatcher creation timed out".into())),
        };

        // Get command sender before moving dispatcher into task
        let command_tx = dispatcher.get_command_sender();

        // Create the manager with ownership of the dispatcher
        let manager = Self {
            dispatcher: Mutex::new(dispatcher),
            command_tx: command_tx.clone(),
            local_addr: [bind_addr, bind_addr, bind_addr], // Triple redundancy
            active: AtomicBool::new(true),
        };

        // Create a separate dispatcher for the background task
        let bind_addr_clone = bind_addr;
        let task_command_tx = command_tx;

        tokio::spawn(async move {
            // Create a new dispatcher instance for this task
            match UtpDispatcher::new(bind_addr_clone).await {
                Ok(mut task_dispatcher) => {
                    // Run the dispatcher until completion
                    task_dispatcher.run().await;
                },
                Err(e) => {
                    eprintln!("CRITICAL ERROR: Failed to create task dispatcher: {:?}", e);
                }
            }

            // Send a heartbeat periodically to detect shutdown
            loop {
                if task_command_tx.send(DispatcherCommand::Heartbeat).await.is_err() {
                    // Channel closed, exit loop
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(manager)
    }

    pub async fn create_connection(&self, remote_addr: SocketAddr) -> Result<Mutex<UtpSocket>, UtpError> {
        // Check active state atomically
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        // Get local address with triple redundancy check
        let local_addr = self.get_local_addr()?;

        // Create a new socket
        let socket = UtpSocket::new(local_addr, remote_addr);

        // Get connection ID to register
        let conn_id = socket.connection_id();

        // Register with dispatcher with bounded execution time
        let (tx, rx) = oneshot::channel();

        // Time-bounded command send
        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS / 2),
            self.command_tx.send(
                DispatcherCommand::RegisterSocketInfo(remote_addr, conn_id, tx)
            )
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to register socket".into()))?,
            Err(_) => return Err(UtpError::Internal("Register socket command timed out".into())),
        };

        // Time-bounded confirmation wait
        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS / 2),
            rx
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to confirm socket registration".into()))?,
            Err(_) => return Err(UtpError::Internal("Registration confirmation timed out".into())),
        };

        // Return the socket wrapped in a Mutex
        Ok(Mutex::new(socket))
    }

    pub fn get_command_sender(&self) -> mpsc::Sender<DispatcherCommand> {
        self.command_tx.clone()
    }

    pub async fn listen(&self) -> Result<UtpListener, UtpError> {
        // Check active state atomically
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Socket manager is inactive".into()));
        }

        // Get local address with triple redundancy check
        let local_addr = self.get_local_addr()?;

        // Create channel for incoming connections
        let (listener_tx, listener_rx) = mpsc::channel(MAX_PENDING_CONNECTIONS);

        // Time-bounded dispatcher lock and registration
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

        // Create the listener
        Ok(UtpListener {
            local_addr: [local_addr, local_addr, local_addr], // Triple redundancy
            dispatcher_tx: self.command_tx.clone(),
            incoming: listener_rx,
            active: AtomicBool::new(true),
        })
    }

    pub async fn shutdown(&self) -> Result<(), UtpError> {
        // Mark as inactive first to prevent new operations
        self.active.store(false, Ordering::Release);

        // Time-bounded shutdown
        match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            self.command_tx.send(DispatcherCommand::Shutdown)
        ).await {
            Ok(result) => result.map_err(|_| UtpError::Internal("Failed to send shutdown command".into()))?,
            Err(_) => return Err(UtpError::Internal("Shutdown command timed out".into())),
        };

        Ok(())
    }

    // Triple modular redundancy for SEU protection
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

        // All three copies differ - critical error
        Err(UtpError::Internal("Local address data corruption detected".into()))
    }
}

pub struct UtpListener {
    local_addr: [SocketAddr; TMR_SIZE], // Triple redundancy for SEU protection
    dispatcher_tx: mpsc::Sender<DispatcherCommand>,
    incoming: mpsc::Receiver<Mutex<UtpSocket>>,
    active: AtomicBool,
}

impl UtpListener {
    pub async fn accept(&mut self) -> Result<(UtpSocket, SocketAddr), UtpError> {
        // Check active state atomically
        if !self.active.load(Ordering::Acquire) {
            return Err(UtpError::Internal("Listener is inactive".into()));
        }

        // Time-bounded accept operation
        let socket_mutex = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS * 5), // Longer timeout for accept
            self.incoming.recv()
        ).await {
            Ok(Some(socket)) => socket,
            Ok(None) => return Err(UtpError::Internal("Listener channel closed".into())),
            Err(_) => return Err(UtpError::Internal("Accept operation timed out".into())),
        };

        // Extract socket information with bounded execution time
        let (remote_addr, socket_info) = match timeout(
            Duration::from_millis(OPERATION_TIMEOUT_MS),
            async {
                let socket_guard = socket_mutex.lock().await;
                let remote_addr = socket_guard.remote_address();
                // Copy any other needed socket information for clone
                let conn_id = socket_guard.connection_id();
                Ok::<_, UtpError>((remote_addr, conn_id))
            }
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(UtpError::Internal("Socket attribute extraction timed out".into())),
        };

        // Get local address with triple redundancy check
        let local_addr = self.get_local_addr()?;

        // Create new socket with existing connection parameters
        let socket = UtpSocket::new(local_addr, remote_addr);

        // Initialize socket with connection ID
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
        // Use get_local_addr with fallback for fault tolerance
        self.get_local_addr().unwrap_or_else(|_| {
            // If all copies are corrupt, use first copy with logged error
            log_error("Critical error: All local_addr copies corrupted");
            self.local_addr[0]
        })
    }

    // Triple modular redundancy for SEU protection
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

impl Drop for UtpListener {
    fn drop(&mut self) {
        // Mark as inactive to prevent new operations
        self.active.store(false, Ordering::Release);

        // Best effort unregister with error handling
        if let Ok(addr) = self.get_local_addr() {
            // Use a fire-and-forget approach for unregistration since we can't await in drop
            let tx = self.dispatcher_tx.clone();
            let _ = tx.try_send(DispatcherCommand::UnregisterListener(addr));
        }
    }
}

// Helper function to check if shutdown was requested
async fn is_shutdown_requested(tx: &mpsc::Sender<DispatcherCommand>) -> bool {
    // Try to send a heartbeat command to see if the channel is still open
    match tx.send(DispatcherCommand::Heartbeat).await {
        Ok(_) => false,
        Err(_) => true, // Channel closed, likely due to shutdown
    }
}

// Critical error logging function
fn log_error(message: &str) {
    eprintln!("CRITICAL ERROR: {}", message);

    #[cfg(feature = "logging")]
    {
        // Since feature isn't defined, we add proper cfg handling
        crate::log::critical(message);
    }
}
