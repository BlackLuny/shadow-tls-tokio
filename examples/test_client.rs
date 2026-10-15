//! Test client to verify communication with original shadow-tls v3 server

use std::env;
use shadow_tls::{ShadowTlsClient, V3Mode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .init();

    // Get configuration from environment or use defaults
    let server_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8002".to_string());
    let sni = env::var("SNI").unwrap_or_else(|_| "www.bing.com".to_string());
    let password = env::var("PASSWORD").unwrap_or_else(|_| "test".to_string());

    println!("=== ShadowTLS V3 Client Test ===");
    println!("Server: {}", server_addr);
    println!("SNI: {}", sni);
    println!();

    let sni_list = vec![sni];

    println!("Creating ShadowTLS client...");
    let client = ShadowTlsClient::new(
        server_addr.clone(),
        sni_list,
        password,
        None,
        V3Mode::Lossy,
    )?;

    // Start a local listener for the test
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    println!("Local test listener on {}", local_addr);

    // Spawn the client relay task
    let client_clone = client.clone();
    let server_addr_clone = server_addr.clone();
    let relay_handle = tokio::spawn(async move {
        // Accept connection from test
        let (in_stream, _) = listener.accept().await.unwrap();
        in_stream.set_nodelay(true).unwrap();
        
        // Connect to shadow-tls server
        let server_stream = TcpStream::connect(&server_addr_clone).await.unwrap();
        server_stream.set_nodelay(true).unwrap();
        
        println!("Starting relay...");
        match client_clone.relay(in_stream, server_stream).await {
            Ok(_) => println!("Relay finished normally"),
            Err(e) => eprintln!("Relay error: {}", e),
        }
    });

    // Give listener time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect to local listener
    let mut test_stream = TcpStream::connect(local_addr).await?;
    test_stream.set_nodelay(true)?;
    println!("Connected to local relay");

    // Test echo: send data immediately (relay will buffer it)
    let test_data = b"Hello, ShadowTLS V3!\n";
    println!("Sending test data: {:?}", String::from_utf8_lossy(test_data));
    
    test_stream.write_all(test_data).await?;
    test_stream.flush().await?;
    println!("Data sent, waiting for echo response...");

    // Read response with longer timeout
    let mut response = vec![0u8; 1024];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        test_stream.read(&mut response),
    ).await;

    match timeout {
        Ok(Ok(n)) => {
            if n > 0 {
                println!("Received {} bytes: {:?}", n, String::from_utf8_lossy(&response[..n]));
                if response[..n].starts_with(test_data) || &response[..n] == test_data {
                    println!("✅ Echo test PASSED!");
                } else {
                    println!("⚠️ Response received but doesn't match exactly (may be OK for some echo servers)");
                }
            } else {
                println!("❌ Connection closed (0 bytes read)");
            }
        }
        Ok(Err(e)) => {
            println!("❌ Read error: {}", e);
        }
        Err(_) => {
            println!("❌ Timeout waiting for response (10s)");
        }
    }

    // Clean up
    drop(test_stream);
    
    // Wait for relay to finish
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_handle).await;

    Ok(())
}
