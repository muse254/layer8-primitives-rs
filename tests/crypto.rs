use layer8_primitives_rs::crypto::{generate_key_pair, KeyUse};

#[test]
fn jwt_to_derivatives_test() {
    let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
    // able to change to public key and private key derivatives
    _ = private_key.public_key_derivative().unwrap();
    _ = private_key.secret_key_derivative().unwrap();
    _ = public_key.public_key_derivative().unwrap();
    assert!(public_key.secret_key_derivative().is_err());
}

#[test]
fn encrypt_decrypt_test() {
    let payload = b"Hello, World!";
    let (private_key, public_key) = generate_key_pair(KeyUse::Ecdh).unwrap();
    let symmetric_key = private_key.get_ecdh_shared_secret(&public_key).unwrap();
    let encrypted = symmetric_key.symmetric_encrypt(payload).unwrap();
    let decrypted = symmetric_key.symmetric_decrypt(&encrypted).unwrap();

    assert_eq!(payload, decrypted.as_slice());
}
