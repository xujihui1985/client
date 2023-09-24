use std::{fs::File, io::BufReader, net::SocketAddr};

use tower::{make::Shared, ServiceExt};
use axum::{handler::Handler, routing::{self, get}, response::IntoResponse, response::Response, body, Router};
use hyper::{
    server::conn::AddrIncoming,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Method, Request, Server, StatusCode, Client,
};

use hyper_rustls::TlsAcceptor;
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::net::{TcpStream};

struct Proxy {
    port: u16,
}

pub async fn serve_http() -> Result<(), hyper::Error> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    // let incoming = AddrIncoming::bind(&addr).unwrap();
    let router_svc = Router::new().route("/*key", get(reverse_proxy));

    let service = service_fn(move |req: Request<Body>| {
        let router_svc = router_svc.clone();
        async move {
            if req.method() == Method::CONNECT {
                proxy(req).await
            } else {
                println!("111111111 handle req {:?}", req);
                // http_proxy(req).await
                router_svc.oneshot(req).await.map_err(|err| match err {})
            }
        }
    });

    axum::Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(Shared::new(service)).await?;
    Ok(())
}

async fn http_proxy(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("handle reverse proxy req {:?}", req);
    let client = Client::new();
    let res = client.request(req).await.unwrap();
    Ok(res)
}

async fn proxy(req: Request<Body>) -> Result<Response, hyper::Error> {
    println!("{:?}", req);

    if let Some(host_addr) = req.uri().authority().map(|auth| auth.to_string()) {
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, &host_addr).await {
                        println!("server io error: {}", e);
                    };
                }
                Err(e) => println!("upgrade error: {}", e),
            }
        });
        Ok((
            StatusCode::OK,
            "CONNECT must be to a socket address",
        )
            .into_response())

        // Ok(Response::new(body::boxed(body::Empty::new())))
    } else {
        println!("CONNECT host is not socket addr: {:?}", req.uri());
        Ok((
            StatusCode::BAD_REQUEST,
            "CONNECT must be to a socket address",
        )
            .into_response())
    }
}



async fn reverse_proxy(req: Request<Body>) -> impl IntoResponse {
    println!("handle reverse proxy req {:?}", req);
    let client = Client::new();
    let res = client.request(req).await.unwrap();
    res
}

async fn serve() {
    let cfg = load_key_pair("./cert.pem", "./key.pem");
    let addr = format!("127.0.0.1:{}", 8080).parse().unwrap();
    //get_incomming(true);
    let incoming = AddrIncoming::bind(&addr).unwrap();
    if true {
        let acceptor = TlsAcceptor::builder()
            .with_tls_config(cfg)
            .with_all_versions_alpn()
            .with_incoming(incoming);

        let service = make_service_fn(|_| async { Ok::<_, std::io::Error>(service_fn(echo)) });
        let server = Server::builder(acceptor).serve(service);
        server.await.unwrap();
    } else {
        let service = make_service_fn(|_| async { Ok::<_, std::io::Error>(service_fn(echo)) });
        let server = Server::builder(incoming).serve(service);
        server.await.unwrap();
    }
}

fn load_key_pair(cert_path: &str, key_path: &str) -> ServerConfig {
    let cert = load_certificates_from_pem(cert_path).unwrap();
    let key = load_private_key_from_file(key_path).unwrap();

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    config
}

fn load_private_key_from_file(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let key_file = File::open(path).expect("cannot open key file");
    let mut key_reader = BufReader::new(key_file);
    let mut keys =
        rustls_pemfile::pkcs8_private_keys(&mut key_reader).expect("cannot read key file");
    match keys.len() {
        0 => Err(format!("No PKCS8-encoded private key found in {path}").into()),
        1 => Ok(PrivateKey(keys.remove(0))),
        _ => Err(format!("More than one PKCS8-encoded private key found in {path}").into()),
    }
}

fn load_certificates_from_pem(path: &str) -> std::io::Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

async fn tunnel(mut upgraded: Upgraded, addr: &str) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    println!("client wrote {from_client} bytes and received {from_server} bytes");

    Ok(())
}
