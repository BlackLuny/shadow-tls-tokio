//! Integration test for ShadowTLS stream API (ShadowTlsClientStream and ShadowTlsServerStream)
//!
//! This test verifies that the async stream API versions of ShadowTLS client and server
//! can correctly communicate through multiple request-response rounds.
//!
//! Usage:
//!   cargo run --example stream_api_test
//!
//! Environment variables:
//!   RUST_LOG=debug  - Enable debug logging

use shadow_tls::{ShadowTlsClient, ShadowTlsServer, TlsAddrs, V3Mode};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

const PASSWORD: &str = "123xxx";
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

    println!("=== ShadowTLS Stream API Test ===");
    println!("Testing: ShadowTlsClientStream and ShadowTlsServerStream");
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
                                    let response =
                                        format!("ECHO: {}", String::from_utf8_lossy(&buf[..n]));
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

    // Step 2: Start the ShadowTLS server using the stream API
    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    println!("ShadowTLS server listening on {}", server_addr);

    // TLS address format: "sni:hostname:port;fallback"
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

                            // Use the stream API: accept() returns ShadowTlsServerStream
                            match server
                                .accept(stream, |handshake_addr| async move {
                                    println!(
                                        "[Server] Connecting to handshake server: {}",
                                        handshake_addr
                                    );
                                    TcpStream::connect(handshake_addr).await
                                })
                                .await
                            {
                                Ok((mut shadow_stream, initial_data)) => {
                                    println!(
                                        "[Server] Accept success, initial data: {} bytes",
                                        initial_data.len()
                                    );

                                    // Connect to the echo server
                                    match TcpStream::connect(&echo_addr_str).await {
                                        Ok(mut echo_stream) => {
                                            echo_stream.set_nodelay(true).ok();

                                            // Send initial data to echo server if any
                                            if !initial_data.is_empty() {
                                                if let Err(e) =
                                                    echo_stream.write_all(&initial_data).await
                                                {
                                                    println!(
                                                        "[Server] Failed to send initial data: {}",
                                                        e
                                                    );
                                                    return;
                                                }
                                            }

                                            // Bidirectional copy between shadow_stream and echo_stream
                                            match tokio::io::copy_bidirectional(
                                                &mut shadow_stream,
                                                &mut echo_stream,
                                            )
                                            .await
                                            {
                                                Ok((a, b)) => {
                                                    println!(
                                                        "[Server] Relay finished: {} bytes to echo, {} bytes from echo",
                                                        a, b
                                                    );
                                                }
                                                Err(e) => {
                                                    println!("[Server] Relay error: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!(
                                                "[Server] Failed to connect to echo server: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("[Server] Accept error: {}", e);
                                }
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

    // Step 3: Create ShadowTLS client and test communication using stream API
    println!("\n--- Starting Client Stream API Test ---\n");

    let client = ShadowTlsClient::new(
        server_addr.to_string(),
        vec![SNI.to_string()],
        PASSWORD.to_string(),
        None,
        V3Mode::Lossy,
    )?;

    // Barrier to synchronize client connection
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();

    // Spawn the client stream task
    let client_clone = client.clone();
    let server_addr_clone = server_addr.to_string();
    let client_stream_handle = tokio::spawn(async move {
        // Connect to shadow-tls server
        let server_stream = match TcpStream::connect(&server_addr_clone).await {
            Ok(s) => s,
            Err(e) => {
                println!("[Client] Failed to connect to server: {}", e);
                return;
            }
        };
        server_stream.set_nodelay(true).unwrap();

        println!("[Client] Connected to ShadowTLS server, starting handshake...");

        // Use the stream API: connect() returns ShadowTlsClientStream
        match client_clone.connect(server_stream).await {
            Ok(mut shadow_stream) => {
                println!("[Client] Handshake complete, stream ready!");
                barrier_clone.wait().await;

                // Perform multiple rounds of request-response
                let mut success_count = 0;
                let mut fail_count = 0;

                for round in 1..=NUM_ROUNDS {
                    println!("\n--- Round {} ---", round);

                    let request = format!(
                        "Request #{}: Hello from client stream API at {:?}",
                        round,
                        std::time::Instant::now()
                    );
                    println!("[Client] Sending: {}", request);

                    // Send request using the stream API
                    if let Err(e) = shadow_stream.write_all(request.as_bytes()).await {
                        println!("[Client] ❌ Write error: {}", e);
                        fail_count += 1;
                        continue;
                    }
                    if let Err(e) = shadow_stream.flush().await {
                        println!("[Client] ❌ Flush error: {}", e);
                        fail_count += 1;
                        continue;
                    }

                    // Read response with timeout
                    let mut response = vec![0u8; 4096];
                    let timeout_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        shadow_stream.read(&mut response),
                    )
                    .await;

                    match timeout_result {
                        Ok(Ok(n)) if n > 0 => {
                            let response_str = String::from_utf8_lossy(&response[..n]);
                            println!("[Client] Received {} bytes: {}", n, response_str);

                            // Verify response contains our request
                            let expected_echo = format!("ECHO: {}", request);
                            if response_str == expected_echo {
                                println!("[Client] ✅ Round {} PASSED!", round);
                                success_count += 1;
                            } else if response_str.contains(&format!("Request #{}", round)) {
                                println!("[Client] ✅ Round {} PASSED (partial match)!", round);
                                success_count += 1;
                            } else {
                                println!("[Client] ⚠️ Round {} - Unexpected response", round);
                                fail_count += 1;
                            }
                        }
                        Ok(Ok(_)) => {
                            println!("[Client] ❌ Round {} - Connection closed (0 bytes)", round);
                            fail_count += 1;
                        }
                        Ok(Err(e)) => {
                            println!("[Client] ❌ Round {} - Read error: {}", round, e);
                            fail_count += 1;
                        }
                        Err(_) => {
                            println!("[Client] ❌ Round {} - Timeout (10s)", round);
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
                    println!(
                        "\n🎉 All tests PASSED! Stream API implementation is working correctly."
                    );
                } else if success_count > 0 {
                    println!("\n⚠️ Some tests passed. Check logs for details.");
                } else {
                    println!("\n❌ All tests FAILED. Stream API implementation needs debugging.");
                }
            }
            Err(e) => {
                println!("[Client] Handshake failed: {}", e);
                barrier_clone.wait().await;
            }
        }
    });

    // Wait for client to be ready
    barrier.wait().await;

    // Wait for client to finish
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client_stream_handle,
    )
    .await;

    // Cleanup
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Abort background tasks
    echo_handle.abort();
    server_handle.abort();

    Ok(())
}
