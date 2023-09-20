use crate::models::{ECDSASHA256CurveP256Signature, EdDSACurve25519Signature};
use core::ops::Deref;
use minicbor::bytes::ByteArray;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};
use ockam_vault::Signature;

impl<C> Encode<C> for EdDSACurve25519Signature {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        ByteArray::from(self.0).encode(e, ctx)
    }
}

impl<'b, C> Decode<'b, C> for EdDSACurve25519Signature {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let data = ByteArray::<64>::decode(d, ctx)?;

        Ok(Self(*data.deref()))
    }
}

impl<C> Encode<C> for ECDSASHA256CurveP256Signature {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        ByteArray::from(self.0).encode(e, ctx)
    }
}

impl<'b, C> Decode<'b, C> for ECDSASHA256CurveP256Signature {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let data = ByteArray::<64>::decode(d, ctx)?;

        Ok(Self(*data.deref()))
    }
}

impl From<EdDSACurve25519Signature> for Signature {
    fn from(value: EdDSACurve25519Signature) -> Self {
        Self::new(value.0.to_vec())
    }
}

impl From<ECDSASHA256CurveP256Signature> for Signature {
    fn from(value: ECDSASHA256CurveP256Signature) -> Self {
        Self::new(value.0.to_vec())
    }
}
