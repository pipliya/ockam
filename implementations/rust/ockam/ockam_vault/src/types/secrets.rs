/// A handle to a secret inside a vault.
#[derive(Clone, Debug)]
pub struct HandleToSecret(Vec<u8>);

impl HandleToSecret {
    pub fn value(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn take_value(self) -> Vec<u8> {
        self.0
    }

    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// A handle to signing secret key inside a vault.
pub enum SigningSecretKeyHandle {
    /// Curve25519 key that is only used for EdDSA signatures.
    EdDSACurve25519(HandleToSecret),
    /// Curve P-256 key that is only used for ECDSA SHA256 signatures.
    ECDSASHA256CurveP256(HandleToSecret),
}

impl SigningSecretKeyHandle {
    pub fn handle(&self) -> HandleToSecret {
        match self {
            SigningSecretKeyHandle::EdDSACurve25519(handle) => handle.clone(),
            SigningSecretKeyHandle::ECDSASHA256CurveP256(handle) => handle.clone(),
        }
    }

    pub fn value(&self) -> Vec<u8> {
        let handle = self.handle();

        handle.take_value()
    }
}

/// Key type for Signing. See [`super::signatures::Signature`].
pub enum SigningKeyType {
    /// See [`super::signatures::EdDSACurve25519Signature`]
    EdDSACurve25519,
    /// See [`super::signatures::ECDSASHA256CurveP256Signature`]
    ECDSASHA256CurveP256,
}

/// A handle to a X25519 Secret Key.
pub struct X25519SecretKeyHandle(HandleToSecret);

/// A handle to a secret Buffer (like an HKDF output).
pub struct SecretBufferHandle {
    handle: HandleToSecret,
    length: usize,
}
