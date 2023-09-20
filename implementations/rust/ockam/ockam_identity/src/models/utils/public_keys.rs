use crate::models::{ECDSASHA256CurveP256PublicKey, EdDSACurve25519PublicKey, X25519PublicKey};
use crate::IdentityError;

use ockam_core::{Error, Result};
use ockam_vault::{PublicKey, SecretType};

use core::ops::Deref;
use minicbor::bytes::ByteArray;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

impl<C> Encode<C> for EdDSACurve25519PublicKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        ByteArray::from(self.0).encode(e, ctx)
    }
}

impl<'b, C> Decode<'b, C> for EdDSACurve25519PublicKey {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let data = ByteArray::<32>::decode(d, ctx)?;

        Ok(Self(*data.deref()))
    }
}

impl<C> Encode<C> for X25519PublicKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        ByteArray::from(self.0).encode(e, ctx)
    }
}

impl<'b, C> Decode<'b, C> for X25519PublicKey {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let data = ByteArray::<32>::decode(d, ctx)?;

        Ok(Self(*data.deref()))
    }
}

impl<C> Encode<C> for ECDSASHA256CurveP256PublicKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        ByteArray::from(self.0).encode(e, ctx)
    }
}

impl<'b, C> Decode<'b, C> for ECDSASHA256CurveP256PublicKey {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let data = ByteArray::<65>::decode(d, ctx)?;

        Ok(Self(*data.deref()))
    }
}

impl From<EdDSACurve25519PublicKey> for PublicKey {
    fn from(value: EdDSACurve25519PublicKey) -> Self {
        Self::new(value.0.to_vec(), SecretType::Ed25519)
    }
}

impl From<X25519PublicKey> for PublicKey {
    fn from(value: X25519PublicKey) -> Self {
        Self::new(value.0.to_vec(), SecretType::X25519)
    }
}

impl From<ECDSASHA256CurveP256PublicKey> for PublicKey {
    fn from(value: ECDSASHA256CurveP256PublicKey) -> Self {
        Self::new(value.0.to_vec(), SecretType::NistP256)
    }
}

impl TryFrom<PublicKey> for EdDSACurve25519PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> Result<Self> {
        match value.stype() {
            SecretType::Ed25519 => {
                let data = value
                    .data()
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKeyData)?;
                Ok(Self(data))
            }
            _ => Err(IdentityError::InvalidKeyType.into()),
        }
    }
}

impl TryFrom<PublicKey> for X25519PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> Result<Self> {
        match value.stype() {
            SecretType::X25519 => {
                let data = value
                    .data()
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKeyData)?;
                Ok(Self(data))
            }
            _ => Err(IdentityError::InvalidKeyType.into()),
        }
    }
}

impl TryFrom<PublicKey> for ECDSASHA256CurveP256PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> Result<Self> {
        match value.stype() {
            SecretType::NistP256 => {
                let data = value
                    .data()
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKeyData)?;
                Ok(Self(data))
            }
            _ => Err(IdentityError::InvalidKeyType.into()),
        }
    }
}
