use aes_gcm::{
    aead::{Aead, Nonce},
    AeadCore, KeyInit,
};
use base64::{self, engine::general_purpose::URL_SAFE as base64_enc_dec, Engine as _};
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

/// Key use.
pub enum KeyUse {
    Ecdsa,
    Ecdh,
}

/// JSON Web Key (JWK) format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Jwk {
    /// The operations that the key is intended to be used for.
    /// Enum: ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
    #[serde(rename = "use")]
    pub key_ops: Vec<String>,
    /// The key type: "EC", "RSA"
    #[serde(rename = "kty")]
    pub key_type: String,
    /// The key ID
    #[serde(rename = "kid")]
    pub key_id: String,
    /// The elliptic curve used with the key. Enum: ["P-256", ...]
    pub crv: String,
    /// The x coordinate as base64 URL encoded string.
    #[serde(rename = "x")]
    pub coordinate_x: String,
    /// The y coordinate as base64 URL encoded string.
    #[serde(rename = "y")]
    pub coordinate_y: String,
    /// The d coordinate as base64 URL encoded string. Private keys only.
    #[serde(rename = "d")]
    pub coordinate_d: Option<String>,
}

// AES-GCM uses a nonce size of 12 bytes. Reference: https://crypto.stackexchange.com/a/41610
const NONCE_SIZE: usize = 12;

/// This function generates a key pair of the provided key use.
pub fn generate_key_pair(key_use: KeyUse) -> Result<(Jwk, Jwk), String> {
    let id = {
        let mut id = [0u8; 16];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut id);
        id
    };

    // Generate an ECDSA key pair of the P-256 curve.
    let (secret_key, public_key) = Secp256k1::new().generate_keypair(&mut OsRng);

    let coordinate_d = base64_enc_dec.encode(secret_key.secret_bytes()); // Private key; d coordinate
    let pub_key_uncompressed = public_key.serialize_uncompressed(); // Public key; x and y coordinates
    let coordinate_x = base64_enc_dec.encode(&pub_key_uncompressed[1..33]); // x coordinate
    let coordinate_y = base64_enc_dec.encode(&pub_key_uncompressed[33..]); // y coordinate

    let private_jwk = {
        let private_key_use = match key_use {
            KeyUse::Ecdh => "deriveKey".to_string(),
            KeyUse::Ecdsa => "sign".to_string(),
        };

        Jwk {
            key_type: "EC".to_string(),
            crv: "P-256".to_string(),
            key_id: format!("priv_{}", base64_enc_dec.encode(id)),
            key_ops: vec![private_key_use],
            coordinate_d: Some(coordinate_d),
            coordinate_x: coordinate_x.clone(),
            coordinate_y: coordinate_y.clone(),
        }
    };

    let public_jwk = {
        let pub_key_use = match key_use {
            KeyUse::Ecdh => "deriveKey".to_string(),
            KeyUse::Ecdsa => "verify".to_string(),
        };

        Jwk {
            key_type: "EC".to_string(),
            crv: "P-256".to_string(),
            key_id: format!("pub_{}", base64_enc_dec.encode(id)),
            key_ops: vec![pub_key_use],
            coordinate_x,
            coordinate_y,
            ..Default::default()
        }
    };

    Ok((private_jwk, public_jwk))
}

impl Jwk {
    /// This function encrypts the provided payload using the calling key.
    pub fn symmetric_encrypt(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if !self.key_ops.contains(&"encrypt".to_string()) {
            return Err("receiver key_ops must contain 'encrypt'".to_string());
        }

        let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng);

        let block_cipher = {
            let coordinate_x = base64_enc_dec
                .decode(&self.coordinate_x)
                .map_err(|e| format!("Failed to decode x coordinate: {}", e))?;
            aes_gcm::Aes256Gcm::new_from_slice(&coordinate_x)
                .map_err(|e| format!("Failed to create block cipher: {}", e))?
        };

        let cipher_text = block_cipher
            .encrypt(&nonce, payload)
            .map_err(|e| format!("Failed to encrypt data: {}", e))?;

        Ok([nonce.as_slice(), &cipher_text].concat())
    }

    /// This function decrypts the provided ciphertext using the calling key.
    pub fn symmetric_decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, String> {
        if cipher_text.is_empty() {
            return Err("ciphertext is empty".to_string());
        }

        if !self.key_ops.contains(&"decrypt".to_string()) {
            return Err("receiver key_ops must contain 'decrypt'".to_string());
        }

        let block_cipher = {
            let coordinate_x = base64_enc_dec
                .decode(&self.coordinate_x)
                .map_err(|e| format!("Failed to decode x coordinate: {}", e))?;
            aes_gcm::Aes256Gcm::new_from_slice(&coordinate_x)
                .map_err(|e| format!("Failed to create block cipher: {}", e))?
        };

        // +-------------------+--------------------+
        // |        Nonce      |   CipherText       |
        // +-------------------+--------------------+
        //  <---- 12 bytes --->
        let (nonce, cipher_text) = cipher_text.split_at(NONCE_SIZE);
        let nonce = Nonce::<aes_gcm::Aes256Gcm>::from_slice(nonce);
        block_cipher
            .decrypt(nonce, cipher_text)
            .map_err(|e| format!("Failed to decrypt data: {}", e))
    }

    /// This function derives a shared secret from the calling key and the provided public key.
    pub fn get_ecdh_shared_secret(&self, public_key: &Jwk) -> Result<Jwk, String> {
        // must be a public key
        if public_key.coordinate_d.is_some() {
            return Err("public key must not contain a private key".to_string());
        }

        // must have 'deriveKey' in its key_ops
        if !public_key.key_ops.contains(&"deriveKey".to_string()) {
            return Err("public key must contain 'deriveKey' in its key_ops".to_string());
        }

        // the calling key must be a private key
        if self.coordinate_d.is_none() {
            return Err(
                "The associated type expected a private key, does not contain coordinate_d"
                    .to_string(),
            );
        }

        if !self.key_ops.contains(&"deriveKey".to_string()) {
            return Err("The associated type expected a private key, does not contain 'deriveKey' in key_ops".to_string());
        }

        // getting the secret key's derivation
        let secret_key = self.secret_key_derivative()?;
        let public_key = public_key.public_key_derivative()?;
        let shared_secret = SharedSecret::new(&public_key, &secret_key);

        Ok(Jwk {
            key_type: "EC".to_string(),
            key_ops: vec!["encrypt".to_string(), "decrypt".to_string()],
            key_id: format!("shared_{}", {
                let mut key_id = "shared_".to_string();
                for i in &self.key_id.as_bytes()[4..] {
                    key_id.push(*i as char);
                }
                key_id
            }),
            crv: self.crv.clone(),
            coordinate_x: base64_enc_dec.encode(shared_secret.as_ref()),
            ..Default::default()
        })
    }

    /// This tries to reconstruct the public key from the x and y coordinates.
    /// It will work for both public and private keys.
    pub fn public_key_derivative(&self) -> Result<PublicKey, String> {
        let coordinate_x = base64_enc_dec
            .decode(&self.coordinate_x)
            .map_err(|e| format!("Failed to decode x coordinate: {}", e))?;
        let coordinate_y = base64_enc_dec
            .decode(&self.coordinate_y)
            .map_err(|e| format!("Failed to decode y coordinate: {}", e))?;

        let mut public_key_bytes = [4u8; 65];
        public_key_bytes[1..33].copy_from_slice(&coordinate_x);
        public_key_bytes[33..].copy_from_slice(&coordinate_y);

        PublicKey::from_slice(&public_key_bytes)
            .map_err(|e| format!("Failed to create public key: {}", e))
    }

    /// This tries to reconstruct the secret key from the d coordinate.
    /// It will only work for private keys.
    pub fn secret_key_derivative(&self) -> Result<SecretKey, String> {
        if self.coordinate_d.is_none() {
            return Err("the Jwt does not contain a private key".to_string());
        }

        let coordinate_d = base64_enc_dec
            .decode(self.coordinate_d.clone().unwrap())
            .map_err(|e| format!("Failed to decode d coordinate: {}", e))?;

        SecretKey::from_slice(&coordinate_d)
            .map_err(|e| format!("Failed to create secret key: {}", e))
    }

    /// Encodes the JWK as a base64 string.
    pub fn export_as_base64(&self) -> String {
        let jwk_json =
            serde_json::to_string(self).expect("Jwk implements Serialize and Deserialize");
        base64_enc_dec.encode(jwk_json.as_bytes())
    }
}

/// This function constructs a JWK from a JSON object.
pub fn jwk_from_map(map: serde_json::Map<String, serde_json::Value>) -> Result<Jwk, String> {
    let server_pub_key = map
        .get("server_pubKeyECDH")
        .ok_or("server_pubKeyECDH not found")?
        .clone();
    serde_json::from_value::<Jwk>(server_pub_key)
        .map_err(|e| format!("Failed to deserialize server_pubKeyECDH: {}", e))
}

/// Decodes a base64 string into a JWK.
pub fn base64_to_jwk(user_pub_jwk: &str) -> Result<Jwk, String> {
    let user_pub_jwk_bs = base64_enc_dec
        .decode(user_pub_jwk)
        .map_err(|e| format!("Failure to decode userPubJWK: {}", e))?;
    serde_json::from_slice(&user_pub_jwk_bs)
        .map_err(|e| format!("Failure to encode userPubJWK: {}", e))
}
