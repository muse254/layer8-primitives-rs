use std::{collections::HashMap, fmt::Debug};

use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::crypto::Jwk;

/// This struct represents the proxy server where the data is intended to be sent.
#[derive(Clone, Debug)]
pub struct Client(Url);

/// This serves as extra doc that the client is specifically a proxy client.
type ProxyClient = Client;

/// This function helps create the client using the provided URL.
pub fn new_client(url: &str) -> Result<Client, String> {
    url::Url::parse(url).map_err(|e| e.to_string()).map(Client)
}

impl ProxyClient {
    /// Handles the exchange to the proxy server. It encrypts the request, sends it and decrypts the response.
    pub async fn r#do(
        &self,
        request: &Request,
        shared_secret: &Jwk,
        backend_url: &str,
        is_static: bool,
        up_jwt: &str,
        uuid: &str,
    ) -> Result<Response, String> {
        self.transfer(request, shared_secret, backend_url, is_static, up_jwt, uuid)
            .await
    }

    async fn transfer(
        &self,
        request: &Request,
        shared_secret: &Jwk,
        backend_url: &str,
        is_static: bool,
        up_jwt: &str,
        uuid: &str,
    ) -> Result<Response, String> {
        if up_jwt.is_empty() || uuid.is_empty() {
            return Err("up_jwt and uuid are required".to_string());
        }

        let response_data = self
            .do_(request, shared_secret, backend_url, is_static, up_jwt, uuid)
            .await?;
        serde_json::from_slice::<Response>(&response_data).map_err(|e| e.to_string())
    }

    async fn do_(
        &self,
        request: &Request,
        shared_secret: &Jwk,
        backend_url: &str,
        is_static: bool,
        up_jwt: &str,
        uuid: &str,
    ) -> Result<Vec<u8>, String> {
        let request_data = RoundtripEnvelope::encode(
            &shared_secret
                .symmetric_encrypt(
                    &serde_json::to_vec(request)
                        .map_err(|e| format!("Failed to serialize request: {}", e))?,
                )
                .map_err(|e| format!("Failed to encrypt request: {}", e))?,
        )
        .to_json_bytes();

        let parsed_backend_url = Url::parse(backend_url).map_err(|e| e.to_string())?;
        let (proxy_url, forward_to_host) = {
            let mut proxy_url = self
                .0
                .join(parsed_backend_url.path())
                .map_err(|e| e.to_string())?;

            if let Some(query) = parsed_backend_url.query() {
                proxy_url.set_query(Some(query));
            }

            let mut forward_to_host = parsed_backend_url
                .host_str()
                .ok_or_else(|| "backend_url expected to have a host".to_string())?
                .to_string();

            if let Some(port) = &parsed_backend_url.port() {
                forward_to_host.push_str(&format!(":{}", port));
            }

            (proxy_url, forward_to_host)
        };

        // adding headers
        let mut header_map = reqwest::header::HeaderMap::new();
        {
            header_map.insert(
                "X-Forwarded-Host",
                forward_to_host
                    .parse()
                    .expect("expected host as header value to be valid; qed"),
            );

            header_map.insert(
                "X-Forwarded-Proto",
                HeaderValue::from_str(parsed_backend_url.scheme())
                    .expect("expected scheme to be valid; qed"),
            );

            header_map.insert(
                "Content-Type",
                HeaderValue::from_str("application/json")
                    .expect("expected content type to be valid; qed"),
            );

            header_map.insert(
                "up-JWT",
                HeaderValue::from_str(up_jwt).expect("expected up-JWT to be valid; qed"),
            );

            header_map.insert(
                "x-client-uuid",
                HeaderValue::from_str(uuid).expect("expected x-client-uuid to be valid; qed"),
            );

            if is_static {
                header_map.insert(
                    "X-Static",
                    HeaderValue::from_str("true").expect("expected X-Static to be valid; qed"),
                );
            }
        }

        let server_resp = reqwest::Client::new()
            .post(proxy_url.as_str())
            .body(request_data)
            .headers(header_map)
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let body = server_resp
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let response_data = RoundtripEnvelope::from_json_bytes(&body)
            .map_err(|e| {
                format!(
                    "Failed to parse json response: {}\n Body is: {}",
                    e,
                    String::from_utf8_lossy(&body)
                )
            })?
            .decode()
            .map_err(|e| format!("Failed to decode response: {}", e))?;

        shared_secret
            .symmetric_decrypt(&response_data)
            .map_err(|e| format!("Failed to decrypt response: {}", e))
    }
}

/// This struct represents the request that is intended to be sent to the backend server to be processed by the middleware.
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Request {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,

    /// This points to the absolute path of the URL. Including any query parameters if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "__url_path")]
    pub url_path: Option<String>,
}

/// This struct represents the response that is received from the backend server and packaged by the middleware.
#[derive(Serialize, Deserialize, Default)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// This struct is used to serialize and deserialize the encrypted data, for the purpose of
/// "round-tripping" the data through the proxy server.
#[derive(Deserialize, Serialize)]
pub struct RoundtripEnvelope {
    pub data: String,
}

impl RoundtripEnvelope {
    fn encode(data: &[u8]) -> Self {
        let mut val = String::new();
        base64_enc_dec.encode_string(data, &mut val);
        RoundtripEnvelope { data: val }
    }

    fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        let mut val = Vec::new();
        base64_enc_dec.decode_vec(&self.data, &mut val)?;
        Ok(val)
    }

    fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("RoundtripEnvelope implements Serialize")
    }

    fn from_json_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServeStatic {
    pub __url_path: String,
}
