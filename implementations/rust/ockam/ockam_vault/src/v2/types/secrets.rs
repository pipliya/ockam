pub struct KeyId(pub String);

pub enum SigningSecretType {
    EdDSACurve25519,
    ECDSASHA256CurveP256,
}

pub struct SigningSecretKeyId {
    pub key_id: KeyId,
    pub stype: SigningSecretType,
}

pub struct X25519SecretKeyId(pub KeyId);

pub struct BufferSecretKeyId {
    pub key_id: KeyId,
    pub length: usize,
}

pub enum AesType {
    Aes256,
    Aes128,
}

pub struct AesSecretKeyId {
    pub key_id: KeyId,
    pub stype: AesType,
}
