use crate::v2::{Signature, VerifyingPublicKey};

use ockam_core::{async_trait, compat::boxed::Box, Result};

#[async_trait]
pub trait VaultForSigning: Send + Sync + 'static {
    async fn sha256(&self, data: &[u8]) -> Result<[u8; 32]>;

    async fn verify_signature(
        &self,
        verifying_public_key: &VerifyingPublicKey,
        data: &[u8],
        signature: &Signature,
    ) -> Result<bool>;
}
