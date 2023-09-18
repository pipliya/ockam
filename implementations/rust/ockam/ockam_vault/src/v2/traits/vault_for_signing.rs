use crate::v2::{Signature, SigningSecretKeyId, SigningSecretType, VerifyingPublicKey};

use ockam_core::{async_trait, compat::boxed::Box, Result};

#[async_trait]
pub trait VaultForSigning: Send + Sync + 'static {
    async fn generate_key(
        &self,
        signing_secret_type: SigningSecretType,
    ) -> Result<SigningSecretKeyId>;

    async fn delete_key(&self, key_id: SigningSecretKeyId) -> Result<bool>;

    async fn get_public_key(&self, key_id: &SigningSecretKeyId) -> Result<VerifyingPublicKey>;

    async fn get_key_id(&self, public_key: &SigningSecretKeyId) -> Result<SigningSecretKeyId>;

    async fn sign(&self, key_id: &SigningSecretKeyId, data: &[u8]) -> Result<Signature>;
}
