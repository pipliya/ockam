pub enum VerifyingPublicKey {
    EdDSACurve25519PublicKey(EdDSACurve25519PublicKey),
    ECDSASHA256CurveP256PublicKey(ECDSASHA256CurveP256PublicKey),
}

/// Curve25519 Public Key that is only used for EdDSA signatures.
///
/// EdDSA Signature as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
///
/// Curve25519 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdDSACurve25519PublicKey(pub [u8; 32]);

/// Curve P-256 Public Key that is only used for ECDSA SHA256 signatures.
/// This type only supports the uncompressed form which is 65 bytes long.
///
/// ECDSA Signature as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
///
/// SHA256 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///
/// Curve P-256 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSASHA256CurveP256PublicKey(pub [u8; 65]);

/// X25519 Public Key is used for ECDH.
///
/// X25519 as defined here:
/// https://datatracker.ietf.org/doc/html/rfc7748
///
/// Curve25519 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);
