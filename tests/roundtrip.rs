use std::{collections::HashMap, time::SystemTime};

use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use layer8_primitives_rs::{
    crypto::{generate_key_pair, jwk_from_map, KeyUse},
    types::{self, Request},
};

// Claims is an arbitrary struct that will be encoded to a JWT.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    expires_at: i64,
}

#[tokio::test]
async fn roundtrip_test() {
    let mock_server = http_mock_server::start_server().await.unwrap();

    // initializing the tunnel
    let uuid = Uuid::new_v4().to_string();
    let (priv_key_client, pub_key_client) = generate_key_pair(KeyUse::Ecdh).unwrap();
    let base64_pub_key = pub_key_client.export_as_base64();

    let body = base64_pub_key.clone();
    let resp = reqwest::Client::new()
        .get(mock_server.url() + "/init-tunnel")
        .header("x-ecdh-init", base64_pub_key.clone())
        .header("x-client-uuid", uuid.clone())
        .body(body)
        .send()
        .await
        .unwrap();

    let up_jwt = resp.headers().get("up_JWT").cloned();
    let data = &resp.bytes().await.unwrap();
    let server_jwk =
        jwk_from_map(serde_json::from_slice::<serde_json::Map<String, Value>>(data).unwrap())
            .unwrap();

    let symmetric_key = priv_key_client.get_ecdh_shared_secret(&server_jwk).unwrap();

    let req = Request {
        method: "GET".to_string(),
        headers: HashMap::from([
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Test-Header".to_string(), "test".to_string()),
        ]),
        body: br#"{"test": "test"}"#.to_vec(),
    };

    // doing a transfer call
    {
        let backend_url = "https://test.layer8.com/test";
        let client = types::new_client(&mock_server.url()).unwrap();

        let resp = client
            .r#do(
                &req,
                &symmetric_key,
                backend_url,
                false,
                up_jwt.unwrap().to_str().unwrap(),
                &uuid,
            )
            .await
            .expect("issue calling the endpoint");

        assert!(resp.status == 200);
    }

    mock_server.close().await.unwrap();
}

fn generate_token(secret_key: &str) -> Result<String, String> {
    let claims = Claims {
        expires_at: SystemTime::now()
            .checked_add(std::time::Duration::from_secs(60 * 60 * 24 * 7))
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let secret_key = EncodingKey::from_secret(secret_key.as_ref());
    jsonwebtoken::encode(&header, &claims, &secret_key).map_err(|e| e.to_string())
}

#[tokio::test]
async fn test_mock_server() {
    // on drop the server should shutdown
    let mock_server = http_mock_server::start_server().await.unwrap();
    let resp = reqwest::get(mock_server.url() + "/hello").await.unwrap();

    // ensure successful response
    assert!(resp.status().is_success());

    // ensure the response body is "Hello, World!"
    assert_eq!(resp.text().await.unwrap(), "Hello, World!");

    // ensure the server is shutdown
    assert!(mock_server.close().await.is_ok());
}

mod http_mock_server {
    use std::{
        collections::HashMap,
        convert::Infallible,
        net::{Ipv4Addr, SocketAddrV4},
        sync::{Arc, Mutex},
    };

    use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
    use http_body_util::{BodyExt, Full};
    use hyper::{
        body::{Body, Bytes, Incoming},
        http::response,
        server::conn::http1,
        Request, Response,
    };
    use hyper_util::rt::TokioIo;
    use layer8_primitives_rs::{
        crypto::{base64_to_jwk, generate_key_pair, Jwk, KeyUse},
        types,
    };
    use tokio::{net::TcpListener, sync::oneshot};
    use tower::ServiceBuilder;

    use crate::generate_token;

    pub struct MockServer {
        pub port: u16,
        pub join_handle: tokio::task::JoinHandle<()>,
        shutdown_signal: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl MockServer {
        pub fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        pub async fn close(self) -> Result<(), String> {
            let sender = self.shutdown_signal.lock().unwrap().take().unwrap();
            if sender.send(()).is_err() {
                return Err("Failed to send shutdown signal".to_string());
            } else {
                println!("Shutdown signal sent");
            }

            // the handle should be ok
            if self.join_handle.await.is_err() {
                return Err("Failed to await server shutdown".to_string());
            }

            Ok(())
        }
    }

    pub async fn start_server() -> Result<MockServer, String> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|err| err.to_string())?;

        let port = listener.local_addr().map_err(|err| err.to_string())?.port();

        // Create a one-shot channel for shutdown signaling
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let shutdown_signal = Arc::new(Mutex::new(Some(shutdown_tx)));

        // Spawn the server
        let join_handle = {
            tokio::spawn(async move {
                let shared_key: Arc<Mutex<Option<Jwk>>> = Arc::new(Mutex::new(None));
                loop {
                    tokio::select! {
                        // Accept new connections
                        Ok((socket, _)) = listener.accept() => {
                            let io = TokioIo::new(socket);
                            let shared_key = shared_key.clone();
                            tokio::spawn(async move {

                                let svc = hyper::service::service_fn(|req: Request<Incoming>| {
                                    let value = shared_key.clone();
                                    async move {
                                    let (server_priv_key, server_pub_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
                                    router(&server_priv_key, &server_pub_key, value, req).await
                                }});
                                let svc = ServiceBuilder::new().service(svc);
                                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                                    eprintln!("server error: {}", err);
                                }
                            });
                        },

                        _ = &mut shutdown_rx => {
                            println!("Shutdown signal received. Closing server.");
                            break;  // Exit the loop to terminate the server
                        }
                    }
                }
            })
        };

        Ok(MockServer {
            port,
            join_handle,
            shutdown_signal,
        })
    }

    pub async fn router(
        server_priv_key: &Jwk,
        server_pub_key: &Jwk,
        shared_key: Arc<Mutex<Option<Jwk>>>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        match req.uri() {
            uri if uri.path() == "/hello" => {
                let body = Bytes::from_static(b"Hello, World!");
                Ok(Response::new(Full::new(body)))
            }

            uri if uri.path() == "/init-tunnel" => {
                let token = generate_token("mock_secret").unwrap();
                let client_public_jwk =
                    base64_to_jwk(req.headers().get("x-ecdh-init").unwrap().to_str().unwrap())
                        .unwrap();

                let shared_secret = server_priv_key
                    .get_ecdh_shared_secret(&client_public_jwk)
                    .unwrap();

                let mut shared_key = shared_key.lock().unwrap();
                *shared_key = Some(shared_secret);

                let json_body = Full::new(Bytes::from(
                    serde_json::json!({
                        "up_JWT": token,
                        "server_pubKeyECDH": server_pub_key,
                    })
                    .to_string(),
                ));

                Ok(response::Builder::new()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .header("up_JWT", token)
                    .body(json_body)
                    .unwrap())
            }

            _ => {
                let mut req_body = req.into_body();
                let mut body = Vec::new();

                loop {
                    if req_body.is_end_stream() {
                        break;
                    }

                    let chunk = req_body.frame().await.unwrap().unwrap();
                    body.extend_from_slice(&chunk.into_data().unwrap());
                }

                let req_body = serde_json::from_slice::<HashMap<String, String>>(&body).unwrap();

                // it is expected that the body is encrypted and encoded in base64 format
                // and set to the "data" key of the request body
                let data = base64_enc_dec
                    .decode(req_body.get("data").unwrap())
                    .unwrap();

                _ = server_priv_key
                    .get_ecdh_shared_secret(server_pub_key)
                    .unwrap();

                let shared_key = shared_key.lock().unwrap();
                let decrypted = shared_key
                    .clone()
                    .unwrap()
                    .symmetric_decrypt(&data)
                    .unwrap();

                // Seems confusing that we are deserializing the request again, but bear in mind that the request
                // was encrypted and encoded in base64 format before being sent to the server, and the one on the function signature
                // is a convenience wrapper to mock a http roungtrip call
                //
                // We are only interested in the fact that the request was decrypted successfully
                _ = serde_json::from_slice::<types::Request>(&decrypted).unwrap();

                // encrypt and return response
                let res = types::Response {
                    body: br#"{"test": "test-response"}"#.to_vec(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("X-Test-Header".to_string(), "test-response".to_string()),
                    ],
                    status: 200,
                    status_text: "OK".to_string(),
                };

                let enc_res = shared_key
                    .clone()
                    .unwrap()
                    .symmetric_encrypt(serde_json::to_string(&res).unwrap().as_bytes())
                    .unwrap();

                let enc_res_json = serde_json::json!({
                    "data": base64_enc_dec.encode(&enc_res),
                })
                .to_string();

                Ok(Response::new(Full::new(Bytes::from(enc_res_json))))
            }
        }
    }
}
