use crate::{EDDSA_CURVE25519_PUBLIC_KEY_LENGTH_USIZE, EDDSA_CURVE25519_SIGNATURE_LENGTH_USIZE};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert_eq;

/// Ed25519 private key length.
pub const ED25519_SECRET_LENGTH_U32: u32 = 32;
/// Ed25519 private key length.
pub const EDDSA_CURVE25519_SECRET_KEY_LENGTH_USIZE: usize = 32;

/// NIST P256 private key length.
pub const NIST_P256_SECRET_LENGTH_U32: u32 = 32;
/// NIST P256 private key length.
pub const ECDSA_SHA256_CURVEP256_SECRET_KEY_LENGTH_USIZE: usize = 32;

/// Signing secret binary
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum SigningStoredSecret {
    /// Curve25519 key that is only used for EdDSA signatures.
    EdDSACurve25519([u8; EDDSA_CURVE25519_SECRET_KEY_LENGTH_USIZE]),
    /// Curve P-256 key that is only used for ECDSA SHA256 signatures.
    ECDSASHA256CurveP256([u8; ECDSA_SHA256_CURVEP256_SECRET_KEY_LENGTH_USIZE]),
}

impl From<SigningSecret> for SigningStoredSecret {
    fn from(value: SigningSecret) -> Self {
        match value {
            SigningSecret::EdDSACurve25519(value) => Self::EdDSACurve25519(value),
            SigningSecret::ECDSASHA256CurveP256(value) => Self::ECDSASHA256CurveP256(value),
        }
    }
}

impl From<SigningStoredSecret> for SigningSecret {
    fn from(value: SigningStoredSecret) -> Self {
        match value {
            SigningStoredSecret::EdDSACurve25519(value) => Self::EdDSACurve25519(value),
            SigningStoredSecret::ECDSASHA256CurveP256(value) => Self::ECDSASHA256CurveP256(value),
        }
    }
}

/// Signing secret binary
#[derive(Eq, PartialEq, Clone)]
pub enum SigningSecret {
    /// Curve25519 key that is only used for EdDSA signatures.
    EdDSACurve25519([u8; EDDSA_CURVE25519_SECRET_KEY_LENGTH_USIZE]),
    /// Curve P-256 key that is only used for ECDSA SHA256 signatures.
    ECDSASHA256CurveP256([u8; ECDSA_SHA256_CURVEP256_SECRET_KEY_LENGTH_USIZE]),
}

const_assert_eq!(
    ed25519_dalek::SECRET_KEY_LENGTH,
    EDDSA_CURVE25519_SECRET_KEY_LENGTH_USIZE
);

const_assert_eq!(
    ed25519_dalek::PUBLIC_KEY_LENGTH,
    EDDSA_CURVE25519_PUBLIC_KEY_LENGTH_USIZE
);

const_assert_eq!(
    ed25519_dalek::SIGNATURE_LENGTH,
    EDDSA_CURVE25519_SIGNATURE_LENGTH_USIZE
);
