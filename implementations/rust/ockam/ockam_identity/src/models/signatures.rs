/// EdDSA Ed25519 Signature
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EdDSACurve25519Signature(pub [u8; 64]);

/// ECDSA P256 Signature
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ECDSASHA256CurveP256Signature(pub [u8; 64]);
