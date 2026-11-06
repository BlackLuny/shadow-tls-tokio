use super::*;
use crate::{ShadowTlsServer, TlsAddrs};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{version::TLS13, ServerConfig};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const NAME: &str = "decoy.example";
const PASSWORD: &str = "test password";
const REQUEST: &[u8] = b"authenticated request";
const RESPONSE: &[u8] = b"authenticated response";

#[tokio::test]
async fn connects_over_tcp_with_verified_client_hello() {
    exercise_tcp(true, false).await;
}

#[tokio::test]
async fn relays_over_tcp_with_verified_client_hello() {
    exercise_tcp(true, true).await;
}

#[tokio::test]
async fn rejects_an_untrusted_decoy_certificate() {
    exercise_tcp(false, false).await;
}

async fn exercise_tcp(trust_decoy: bool, relay: bool) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let mut roots = RootCertStore::empty();
    if trust_decoy {
        roots.add(cert.der().clone()).unwrap();
    }
    let mut decoy_config =
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&TLS13])
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
        V3Mode::Strict,
    );
    let client = ShadowTlsClient::new_with_roots(
        proxy_addr.to_string(),
        vec![NAME.into()],
        PASSWORD.into(),
        Some(TlsExtConfig::new(Some(vec![b"h2".to_vec()]))),
        V3Mode::Strict,
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
                let _ = wait_for_proxy.await;
            } else {
                assert!(handshake.is_err());
            }
        };
        let serve_proxy = async {
            let (socket, _) = proxy.accept().await.unwrap();
            let accepted = server.accept(socket, TcpStream::connect).await;
            if trust_decoy {
                let (mut stream, mut initial) = accepted.unwrap();
                assert!(initial.len() <= REQUEST.len());
                let received = initial.len();
                initial.resize(REQUEST.len(), 0);
                stream.read_exact(&mut initial[received..]).await.unwrap();
                assert_eq!(initial, REQUEST);
                stream.write_all(RESPONSE).await.unwrap();
                stream.flush().await.unwrap();
            } else {
                assert!(accepted.is_err());
            }
            let _ = proxy_finished.send(());
        };
        let run_client = async {
            let socket = TcpStream::connect(proxy_addr).await.unwrap();
            if relay {
                let (mut app, transport) = tokio::io::duplex(1024);
                let ((), result) = tokio::join!(exchange(&mut app), client.relay(transport, socket));
                result.unwrap();
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

async fn exchange(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) {
    stream.write_all(REQUEST).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = [0; RESPONSE.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, RESPONSE);
}
