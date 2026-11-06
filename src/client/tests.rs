use super::*;
use crate::{ShadowTlsServer, TlsAddrs};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{
    version::{TLS12, TLS13},
    ServerConfig,
};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const NAME: &str = "decoy.example";
const PASSWORD: &str = "test password";
const REQUEST: &[u8] = b"authenticated request";
const RESPONSE: &[u8] = b"authenticated response";

#[derive(Clone, Copy)]
enum Decoy {
    Tls13,
    Tls13WithRetry,
    Tls12,
}

#[tokio::test]
async fn connects_over_tcp_with_verified_client_hello() {
    exercise_tcp(true, false, V3Mode::Strict, Decoy::Tls13).await;
}

#[tokio::test]
async fn relays_over_tcp_with_verified_client_hello() {
    exercise_tcp(true, true, V3Mode::Strict, Decoy::Tls13).await;
}

#[tokio::test]
async fn rejects_an_untrusted_decoy_certificate() {
    exercise_tcp(false, false, V3Mode::Strict, Decoy::Tls13).await;
}

#[tokio::test]
async fn strict_connects_after_hello_retry_request() {
    exercise_tcp(true, false, V3Mode::Strict, Decoy::Tls13WithRetry).await;
}

#[tokio::test]
async fn strict_relays_after_hello_retry_request() {
    exercise_tcp(true, true, V3Mode::Strict, Decoy::Tls13WithRetry).await;
}

#[tokio::test]
async fn lossy_connects_with_tls12_decoy() {
    exercise_tcp(true, false, V3Mode::Lossy, Decoy::Tls12).await;
}

#[tokio::test]
async fn strict_rejects_a_tls12_decoy() {
    exercise_tcp(true, false, V3Mode::Strict, Decoy::Tls12).await;
}

async fn exercise_tcp(trust_decoy: bool, relay: bool, mode: V3Mode, decoy: Decoy) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let mut roots = RootCertStore::empty();
    if trust_decoy {
        roots.add(cert.der().clone()).unwrap();
    }
    let mut decoy_provider = aws_lc_rs::default_provider();
    if matches!(decoy, Decoy::Tls13WithRetry) {
        // The client initially sends an X25519 share. A P-256-only server must retry.
        decoy_provider.kx_groups = vec![kx_group::SECP256R1];
    }
    let tls_version = match decoy {
        Decoy::Tls12 => &TLS12,
        Decoy::Tls13 | Decoy::Tls13WithRetry => &TLS13,
    };
    let strict_fallback = mode.strict() && matches!(decoy, Decoy::Tls12);
    let mut decoy_config = ServerConfig::builder_with_provider(Arc::new(decoy_provider))
        .with_protocol_versions(&[tls_version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    decoy_config.alpn_protocols = vec![b"h2".to_vec()];
    decoy_config.send_tls13_tickets = 0;
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap().to_string();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = ShadowTlsServer::new(
        "unused backend".into(),
        TlsAddrs::new(decoy_addr),
        PASSWORD.into(),
        mode,
    );
    let client = ShadowTlsClient::new_with_roots(
        proxy_addr.to_string(),
        vec![NAME.into()],
        PASSWORD.into(),
        Some(TlsExtConfig::new(Some(vec![b"h2".to_vec()]))),
        mode,
        roots,
    )
    .unwrap();

    timeout(Duration::from_secs(10), async {
        let (proxy_finished, wait_for_proxy) = tokio::sync::oneshot::channel();
        let serve_decoy = async {
            let (socket, _) = decoy.accept().await.unwrap();
            let handshake = TlsAcceptor::from(Arc::new(decoy_config)).accept(socket).await;
            if trust_decoy {
                let tls = handshake.unwrap();
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                assert_eq!(tls.get_ref().1.protocol_version(), Some(tls_version.version));
                if !strict_fallback {
                    let _ = wait_for_proxy.await;
                }
            } else {
                assert!(handshake.is_err());
            }
        };
        let serve_proxy = async {
            let (socket, _) = proxy.accept().await.unwrap();
            if relay {
                let (transport, mut origin) = tokio::io::duplex(1024);
                let serve_origin = async move {
                    respond(&mut origin, Vec::new()).await;
                    drop(origin);
                };
                let ((), result) = tokio::join!(
                    serve_origin,
                    server.relay(socket, TcpStream::connect, || async { Ok(transport) }),
                );
                result.unwrap();
            } else {
                let accepted = server.accept(socket, TcpStream::connect).await;
                if strict_fallback {
                    assert_eq!(accepted.err().unwrap().kind(), io::ErrorKind::Unsupported);
                } else if trust_decoy {
                    let (mut stream, initial) = accepted.unwrap();
                    respond(&mut stream, initial).await;
                } else {
                    assert!(accepted.is_err());
                }
            }
            let _ = proxy_finished.send(());
        };
        let run_client = async {
            let socket = TcpStream::connect(proxy_addr).await.unwrap();
            if relay {
                let (mut app, transport) = tokio::io::duplex(1024);
                let ((), result) = tokio::join!(exchange(&mut app), client.relay(transport, socket));
                result.unwrap();
            } else if strict_fallback {
                let Err(error) = client.connect(socket).await else {
                    panic!("V3 Strict accepted a TLS 1.2 decoy");
                };
                assert!(error.to_string().contains("TLS1.3 not supported"), "{error}");
            } else if trust_decoy {
                exchange(&mut client.connect(socket).await.unwrap()).await;
            } else {
                let Err(error) = client.connect(socket).await else {
                    panic!("an untrusted decoy completed the handshake");
                };
                assert!(error.to_string().contains("UnknownIssuer"), "{error}");
            }
        };
        tokio::join!(serve_decoy, serve_proxy, run_client);
    })
    .await
    .expect("ShadowTLS TCP fixture timed out");
}

async fn respond(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), mut initial: Vec<u8>) {
    assert!(initial.len() <= REQUEST.len());
    let received = initial.len();
    initial.resize(REQUEST.len(), 0);
    stream.read_exact(&mut initial[received..]).await.unwrap();
    assert_eq!(initial, REQUEST);
    stream.write_all(RESPONSE).await.unwrap();
    stream.flush().await.unwrap();
}

async fn exchange(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) {
    stream.write_all(REQUEST).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0; RESPONSE.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, RESPONSE);
}
