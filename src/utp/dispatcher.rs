// utp/dispatcher.rs

#![allow(dead_code)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{self, Duration, timeout};

use crate::utp::common::{ConnectionState, UtpError, ST_SYN};
use crate::utp::packet::UtpPacket;
use crate::utp::socket::UtpSocket;

/// Maximum packet size for UDP datagrams
const MAX_PACKET_SIZE: usize = 65536;
/// Default tick interval in milliseconds
const TICK_INTERVAL_MS: u64 = 50;
/// Maximum operation timeout in milliseconds
const OPERATION_TIMEOUT_MS: u64 = 100;
/// Maximum number of channels to buffer
const CHANNEL_BUFFER_SIZE: usize = 100;

// The combo of remote addr and connection id uniquely identifies a connection
type ConnectionId = (SocketAddr, u16);

pub struct UtpDispatcher {
    udp_socket: UdpSocket,
    connections: RwLock<HashMap<ConnectionId, Mutex<UtpSocket>>>,
    listeners: RwLock<HashMap<SocketAddr, mpsc::Sender<Mutex<UtpSocket>>>>,
    command_rx: mpsc::Receiver<DispatcherCommand>,
    command_tx: mpsc::Sender<DispatcherCommand>,
    notification_tx: mpsc::Sender<SocketNotification>,
    running: AtomicBool,
}

#[derive(Debug)]
pub enum DispatcherCommand {
    RegisterSocketInfo(SocketAddr, u16, oneshot::Sender<()>),
    UnregisterSocket(ConnectionId, oneshot::Sender<()>),
    SendPacket(ConnectionId, Vec<u8>, SocketAddr),
    Shutdown,
    Heartbeat,
    UnregisterListener(SocketAddr),
}

#[derive(Debug)]
pub enum SocketNotification {
    DataReceived(ConnectionId),
    StateChanged(ConnectionId, ConnectionState),
    ConnectionError(ConnectionId, UtpError),
}

impl UtpDispatcher {
    pub async fn new(bind_addr: SocketAddr) -> Result<Self, UtpError> {
        let udp_socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| UtpError::Network(e))?;

        let (command_tx, command_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (notification_tx, _) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        Ok(Self {
            udp_socket,
            connections: RwLock::new(HashMap::new()),
            listeners: RwLock::new(HashMap::new()),
            command_rx,
            command_tx,
            notification_tx,
            running: AtomicBool::new(true),
        })
    }

    pub fn get_command_sender(&self) -> mpsc::Sender<DispatcherCommand> {
        self.command_tx.clone()
    }

    pub fn create_notification_receiver(&self) -> mpsc::Receiver<SocketNotification> {
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        // We're not actually using tx, but returning rx
        let _ = tx;
        rx
    }

    pub async fn run(&mut self) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        while self.running.load(Ordering::Acquire) {
            tokio::select! {
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(DispatcherCommand::Shutdown) => {
                            self.running.store(false, Ordering::Release);
                            break;
                        },
                        Some(DispatcherCommand::RegisterSocketInfo(remote_addr, conn_id, ack)) => {
                            // Create a new socket and register it
                            let local_addr = match self.udp_socket.local_addr() {
                                Ok(addr) => addr,
                                Err(_) => {
                                    // Can't get local address, still acknowledge
                                    let _ = ack.send(());
                                    continue;
                                }
                            };
                            
                            // Create and initialize socket
                            let socket = UtpSocket::new(local_addr, remote_addr);
                            
                            // Register socket with connection ID
                            {
                                let mut connections = self.connections.write().await;
                                connections.insert((remote_addr, conn_id), Mutex::new(socket));
                            }
                            
                            // Acknowledge registration completed
                            let _ = ack.send(());
                        },
                        Some(DispatcherCommand::UnregisterSocket(conn_id, ack)) => {
                            {
                                let mut connections = self.connections.write().await;
                                connections.remove(&conn_id);
                            }
                            let _ = ack.send(());
                        },
                        Some(DispatcherCommand::SendPacket(_, data, addr)) => {
                            // Send UDP packet with timeout
                            let _ = timeout(
                                Duration::from_millis(OPERATION_TIMEOUT_MS),
                                self.udp_socket.send_to(&data, addr)
                            ).await;
                        },
                        Some(DispatcherCommand::Heartbeat) => {
                            // Heartbeat - no action needed
                        },
                        Some(DispatcherCommand::UnregisterListener(addr)) => {
                            let mut listeners = self.listeners.write().await;
                            listeners.remove(&addr);
                        },
                        None => {
                            self.running.store(false, Ordering::Release);
                            break;
                        }
                    }
                },
                recv_result = self.udp_socket.recv_from(&mut buf) => {
                    if let Ok((size, addr)) = recv_result {
                        self.handle_incoming(&buf[..size], addr).await;
                    }
                },
                _ = time::sleep(Duration::from_millis(TICK_INTERVAL_MS)) => {
                    self.handle_ticks().await;
                }
            }
        }
    }

    pub async fn register_listener(
        &self,
        addr: SocketAddr,
        tx: mpsc::Sender<Mutex<UtpSocket>>
    ) -> Result<(), UtpError> {
        let mut listeners = self.listeners.write().await;
        listeners.insert(addr, tx);
        Ok(())
    }

    async fn handle_incoming(&self, data: &[u8], addr: SocketAddr) {
        // Try to parse the packet
        if let Ok(packet) = UtpPacket::from_bytes(data, addr) {
            let header = &packet.header;
            let conn_id = (addr, header.connection_id());

            // Find the socket for this connection
            let socket_exists = {
                let connections = self.connections.read().await;
                connections.contains_key(&conn_id)
            };

            if socket_exists {
                // Process the incoming data with timeout
                match timeout(
                    Duration::from_millis(OPERATION_TIMEOUT_MS),
                    async {
                        // Get a lock on the specific connection
                        let connections = self.connections.read().await;
                        if let Some(socket) = connections.get(&conn_id) {
                            let mut socket_guard = socket.lock().await;
                            socket_guard.process_incoming_datagram(data, addr);
                            let state = socket_guard.get_state();

                            // Notify about data received and state changes
                            drop(socket_guard); // Release the lock before awaiting

                            let _ = self.notification_tx.send(SocketNotification::DataReceived(conn_id)).await;
                            let _ = self.notification_tx.send(SocketNotification::StateChanged(conn_id, state)).await;
                        }
                    }
                ).await {
                    Ok(_) => {}, // Success
                    Err(_) => {
                        // Timeout processing packet
                        eprintln!("Timeout processing incoming packet");
                    }
                }
            } else if header.packet_type() == ST_SYN {
                // This is a new connection request
                self.handle_new_connection(data, addr, header.connection_id()).await;
            }
        }
    }

    async fn handle_new_connection(&self, data: &[u8], addr: SocketAddr, conn_id: u16) {
        // Get local address
        let local_addr = match self.udp_socket.local_addr() {
            Ok(addr) => addr,
            Err(_) => return, // Can't determine local address
        };

        // Check if we have a listener for the destination address
        let listener_tx = {
            let listeners = self.listeners.read().await;
            match listeners.get(&local_addr) {
                Some(tx) => tx.clone(),
                None => return, // No listener for this address
            }
        };

        // Create a new socket for this connection
        let mut socket = UtpSocket::new(local_addr, addr);

        // Process the SYN packet
        socket.process_incoming_datagram(data, addr);

        // Register the new socket in connections map
        let new_conn_id = (addr, conn_id.wrapping_add(1)); // Listener's recv_id is SYN's conn_id + 1
        let socket_mutex = Mutex::new(socket);

        // Create a new mutex for the listener
        let listener_socket = UtpSocket::new(local_addr, addr);
        let listener_socket_mutex = Mutex::new(listener_socket);

        {
            let mut connections = self.connections.write().await;
            connections.insert(new_conn_id, socket_mutex);
        }

        // Notify the listener
        if let Err(e) = listener_tx.send(listener_socket_mutex).await {
            eprintln!("Failed to notify listener about new connection: {}", e);
        }
    }

    async fn handle_ticks(&self) {
        // Get a list of all connection IDs
        let connection_ids = {
            let connections = self.connections.read().await;
            connections.keys().copied().collect::<Vec<_>>()
        };

        // Process each connection separately without holding the read lock
        for conn_id in connection_ids {
            // Process a single connection tick with timeout
            match timeout(
                Duration::from_millis(OPERATION_TIMEOUT_MS),
                self.tick_single_connection(conn_id)
            ).await {
                Ok(_) => {}, // Successfully processed or no data to send
                Err(_) => {
                    eprintln!("Timeout while processing connection tick for {:?}", conn_id);
                }
            }
        }
    }

    // Helper method to process a single connection's tick
    async fn tick_single_connection(&self, conn_id: ConnectionId) {
        // Get a read lock and check if the connection exists
        let connections = self.connections.read().await;
        let socket = match connections.get(&conn_id) {
            Some(socket) => socket,
            None => return,
        };

        // Lock the socket and process its tick
        let mut socket_guard = socket.lock().await;

        // Check if there's outgoing data
        if let Ok(Some(data)) = socket_guard.tick() {
            let addr = socket_guard.remote_address();

            // Release the socket lock before sending
            drop(socket_guard);

            // Send the packet
            if let Err(e) = self.udp_socket.send_to(&data, addr).await {
                eprintln!("Failed to send packet: {}", e);
                let _ = self.notification_tx.send(
                    SocketNotification::ConnectionError(
                        conn_id,
                        UtpError::Network(e)
                    )
                ).await;
            }
        }
    }
}
