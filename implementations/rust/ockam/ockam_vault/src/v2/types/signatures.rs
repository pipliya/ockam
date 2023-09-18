pub enum Signature {
    EdDSACurve25519Signature(EdDSACurve25519Signature),
    ECDSASHA256CurveP256Signature(ECDSASHA256CurveP256Signature),
}

/// EdDSA Curve25519 Signature.
///
/// EdDSA Signature as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
///
/// Curve25519 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EdDSACurve25519Signature(pub [u8; 64]);

/// ECDSA SHA256 Curve P-256 Signature.
///
/// ECDSA Signature as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
///
/// SHA256 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///
/// Curve P-256 as defined here:
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ECDSASHA256CurveP256Signature(pub [u8; 64]);
