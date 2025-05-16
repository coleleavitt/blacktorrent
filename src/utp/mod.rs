// utp/mod.rs

// Declare the submodules. Rust will look for socket.rs, packet.rs, etc.,
// in the current directory (utp/).
pub mod common;
pub mod packet;
pub mod socket;
pub mod connection;
pub mod congestion;
pub mod reliability;
pub mod stream;

// Re-export key public types or functions if desired, for easier access from outside the `utp` module.
// For example, if UtpSocket is the main entry point:
pub use socket::UtpSocket;
pub use stream::UtpStream; // If you implement a UtpStream similar to rust-utp[2]
pub use common::UtpError;

/// Initializes the uTP context or any global state if necessary.
/// This is a placeholder; a real implementation might involve setting up
/// a background task for managing sockets or timers.
pub fn initialize() {
    println!("Native uTP module initialized (placeholder from utp/mod.rs)");
    // Potentially set up a global timer, a UDP socket dispatcher, etc.
}

// Example of how the user might interact (conceptual)
// async fn run_utp_client() -> Result<(), UtpError> {
//     let remote_addr = "127.0.0.1:12345".parse().unwrap();
//     let mut stream = UtpStream::connect(remote_addr).await?;
//     stream.write_all(b"Hello uTP from Rust!").await?;
//     let mut buffer = [0u8; 1024];
//     let n = stream.read(&mut buffer).await?;
//     println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
//     stream.close().await?;
//     Ok(())
// }
