/// Ed25519 Public Key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdDSACurve25519PublicKey(pub [u8; 32]);

/// X25519 Public Key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

/// P256 Public Key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSASHA256CurveP256PublicKey(pub [u8; 65]);
