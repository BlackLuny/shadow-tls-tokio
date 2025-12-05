//! Integration test for ShadowTLS client and server communication
//!
//! This test verifies that the tokio-based ShadowTLS server implementation
//! can correctly communicate with the tokio-based client through multiple
//! request-response rounds.
//!
//! Usage:
//!   cargo run --example integration_test
//!
//! Environment variables:
//!   RUST_LOG=debug  - Enable debug logging

use shadow_tls::{ShadowTlsClient, ShadowTlsServer, TlsAddrs, V3Mode};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

const PASSWORD: &str = "test-password-12345";
const SNI: &str = "www.runit.com";
const NUM_ROUNDS: usize = 10;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    println!("=== ShadowTLS Integration Test ===");
    println!("SNI: {}", SNI);
    println!("Password: {}", PASSWORD);
    println!("Test rounds: {}", NUM_ROUNDS);
    println!();

    // Step 1: Start a simple echo server (simulates the backend data server)
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    println!("Echo server listening on {}", echo_addr);

    let echo_handle = tokio::spawn(async move {
        loop {
            match echo_listener.accept().await {
                Ok((mut stream, addr)) => {
                    println!("[Echo] Connection from {}", addr);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => {
                                    println!("[Echo] Connection closed");
                                    break;
                                }
                                Ok(n) => {
                                    println!(
                                        "[Echo] Received {} bytes: {:?}",
                                        n,
                                        String::from_utf8_lossy(&buf[..n])
                                    );
                                    // Echo back with prefix
                                    let response = format!("ECHO: {}", String::from_utf8_lossy(&buf[..n]));
                                    if let Err(e) = stream.write_all(response.as_bytes()).await {
                                        println!("[Echo] Write error: {}", e);
                                        break;
                                    }
                                    if let Err(e) = stream.flush().await {
                                        println!("[Echo] Flush error: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    println!("[Echo] Read error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    println!("[Echo] Accept error: {}", e);
                }
            }
        }
    });

    // Step 2: Start the ShadowTLS server
    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    println!("ShadowTLS server listening on {}", server_addr);

    // TLS address format: "sni:hostname:port;fallback" 
    // We use www.runit.com as the SNI, pointing to the real TLS server
    // Format: "sni:target_host:port;fallback_host:port"
    let tls_addr_str = format!("{}:www.runit.com:443;www.runit.com:443", SNI);
    let tls_addr = TlsAddrs::try_from(tls_addr_str.as_str())?;
    println!("TLS address config: {}", tls_addr);

    let shadow_server = ShadowTlsServer::new(
        echo_addr.to_string(),
        tls_addr,
        PASSWORD.to_string(),
        V3Mode::Lossy, // Use Lossy mode for compatibility
    );

    let server_handle = tokio::spawn({
        let shadow_server = shadow_server.clone();
        async move {
            loop {
                match server_listener.accept().await {
                    Ok((stream, addr)) => {
                        println!("[Server] Connection from {}", addr);
                        let server = shadow_server.clone();
                        let echo_addr_str = echo_addr.to_string();

                        tokio::spawn(async move {
                            stream.set_nodelay(true).ok();
                            match server
                                .relay(
                                    stream,
                                    |handshake_addr| async move {
                                        println!("[Server] Connecting to handshake server: {}", handshake_addr);
                                        TcpStream::connect(handshake_addr).await
                                    },
                                    || async move {
                                        println!("[Server] Connecting to data server: {}", echo_addr_str);
                                        TcpStream::connect(echo_addr_str).await
                                    },
                                )
                                .await
                            {
                                Ok(_) => println!("[Server] Relay finished"),
                                Err(e) => println!("[Server] Relay error: {}", e),
                            }
                        });
                    }
                    Err(e) => {
                        println!("[Server] Accept error: {}", e);
                    }
                }
            }
        }
    });

    // Give servers time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Step 3: Create ShadowTLS client and test communication
    println!("\n--- Starting Client Test ---\n");

    let client = ShadowTlsClient::new(
        server_addr.to_string(),
        vec![SNI.to_string()],
        PASSWORD.to_string(),
        None,
        V3Mode::Lossy,
    )?;

    // Start a local listener for the client
    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_local_addr = client_listener.local_addr()?;
    println!("Client local listener on {}", client_local_addr);

    // Barrier to synchronize client relay start
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();

    // Spawn the client relay task
    let client_clone = client.clone();
    let server_addr_clone = server_addr.to_string();
    let client_relay_handle = tokio::spawn(async move {
        // Accept connection from test
        let (in_stream, _) = client_listener.accept().await.unwrap();
        in_stream.set_nodelay(true).unwrap();

        // Connect to shadow-tls server
        let server_stream = TcpStream::connect(&server_addr_clone).await.unwrap();
        server_stream.set_nodelay(true).unwrap();

        println!("[Client] Starting relay to {}", server_addr_clone);
        barrier_clone.wait().await;

        match client_clone.relay(in_stream, server_stream).await {
            Ok(_) => println!("[Client] Relay finished normally"),
            Err(e) => println!("[Client] Relay error: {}", e),
        }
    });

    // Connect to client local listener
    let mut test_stream = TcpStream::connect(client_local_addr).await?;
    test_stream.set_nodelay(true)?;
    println!("[Test] Connected to client relay");

    // Wait for relay to be ready
    barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Perform multiple rounds of request-response
    let mut success_count = 0;
    let mut fail_count = 0;

    for round in 1..=NUM_ROUNDS {
        println!("\n--- Round {} ---", round);

        let request = format!("Request #{}: Hello from client at {:?}", round, std::time::Instant::now());
        println!("[Test] Sending: {}", request);

        // Send request
        if let Err(e) = test_stream.write_all(request.as_bytes()).await {
            println!("[Test] ❌ Write error: {}", e);
            fail_count += 1;
            continue;
        }
        if let Err(e) = test_stream.flush().await {
            println!("[Test] ❌ Flush error: {}", e);
            fail_count += 1;
            continue;
        }

        // Read response with timeout
        let mut response = vec![0u8; 4096];
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            test_stream.read(&mut response),
        )
        .await;

        match timeout_result {
            Ok(Ok(n)) if n > 0 => {
                let response_str = String::from_utf8_lossy(&response[..n]);
                println!("[Test] Received {} bytes: {}", n, response_str);

                // Verify response contains our request
                let expected_echo = format!("ECHO: {}", request);
                if response_str == expected_echo {
                    println!("[Test] ✅ Round {} PASSED!", round);
                    success_count += 1;
                } else if response_str.contains(&format!("Request #{}", round)) {
                    println!("[Test] ✅ Round {} PASSED (partial match)!", round);
                    success_count += 1;
                } else {
                    println!("[Test] ⚠️ Round {} - Unexpected response", round);
                    fail_count += 1;
                }
            }
            Ok(Ok(_)) => {
                println!("[Test] ❌ Round {} - Connection closed (0 bytes)", round);
                fail_count += 1;
            }
            Ok(Err(e)) => {
                println!("[Test] ❌ Round {} - Read error: {}", round, e);
                fail_count += 1;
            }
            Err(_) => {
                println!("[Test] ❌ Round {} - Timeout (10s)", round);
                fail_count += 1;
            }
        }

        // Small delay between rounds
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Summary
    println!("\n=== Test Summary ===");
    println!("Total rounds: {}", NUM_ROUNDS);
    println!("Successful: {}", success_count);
    println!("Failed: {}", fail_count);

    if success_count == NUM_ROUNDS {
        println!("\n🎉 All tests PASSED! Server implementation is working correctly.");
    } else if success_count > 0 {
        println!("\n⚠️ Some tests passed. Check logs for details.");
    } else {
        println!("\n❌ All tests FAILED. Server implementation needs debugging.");
    }

    // Cleanup
    drop(test_stream);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Abort background tasks
    echo_handle.abort();
    server_handle.abort();
    client_relay_handle.abort();

    Ok(())
}
