use crate::v2::{AesSecretKeyId, BufferSecretKeyId, X25519PublicKey, X25519SecretKeyId};

use ockam_core::{async_trait, compat::boxed::Box, Result};

#[async_trait]
pub trait VaultForSecureChannels: Send + Sync + 'static {
    async fn generate_static_dh_secret(&self) -> Result<X25519SecretKeyId>;

    async fn generate_ephemeral_dh_secret(&self) -> Result<X25519SecretKeyId>;

    async fn delete_dh_secret(&self, key_id: X25519SecretKeyId) -> Result<bool>;

    async fn delete_buffer_secret(&self, key_id: BufferSecretKeyId) -> Result<bool>;

    async fn delete_aes_secret(&self, key_id: AesSecretKeyId) -> Result<bool>;

    async fn get_public_key(&self, key_id: &X25519SecretKeyId) -> Result<X25519PublicKey>;

    async fn get_key_id(&self, public_key: &X25519PublicKey) -> Result<X25519SecretKeyId>;

    async fn ec_diffie_hellman(
        &self,
        key_id: &X25519SecretKeyId,
        peer_public_key: &X25519PublicKey,
    ) -> Result<BufferSecretKeyId>;

    async fn hkdf_sha256(
        &self,
        salt: &BufferSecretKeyId,
        info: &[u8],
        ikm: Option<&BufferSecretKeyId>,
        output_number: usize,
    ) -> Result<Vec<BufferSecretKeyId>>;

    async fn aead_aes_gcm_encrypt(
        &self,
        key_id: &AesSecretKeyId,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;

    async fn aead_aes_gcm_decrypt(
        &self,
        key_id: &AesSecretKeyId,
        cipher_text: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
}
