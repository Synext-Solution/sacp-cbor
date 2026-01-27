#[cfg(feature = "adapter-minicbor")]
mod impls {
    use minicbor::decode::{Decoder, Error as DecodeError};
    use minicbor::encode::{Encoder, Error as EncodeError, Write};
    use minicbor::data::Type;

    use crate::value::BenchValue;

    impl<C> minicbor::Encode<C> for BenchValue {
        fn encode<W: Write>(&self, e: &mut Encoder<W>, _ctx: &mut C) -> Result<(), EncodeError<W::Error>> {
            match self {
                BenchValue::Null => {
                    e.null()?;
                }
                BenchValue::Bool(b) => {
                    e.bool(*b)?;
                }
                BenchValue::Int(i) => {
                    e.i64(*i)?;
                }
                BenchValue::Bytes(b) => {
                    e.bytes(b)?;
                }
                BenchValue::Text(s) => {
                    e.str(s)?;
                }
                BenchValue::Array(items) => {
                    e.array(items.len() as u64)?;
                    for item in items {
                        item.encode(e, _ctx)?;
                    }
                }
                BenchValue::Map(entries) => {
                    e.map(entries.len() as u64)?;
                    for (k, v) in entries {
                        e.str(k)?;
                        v.encode(e, _ctx)?;
                    }
                }
            }
            Ok(())
        }
    }

    impl<'b, C> minicbor::Decode<'b, C> for BenchValue {
        fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, DecodeError> {
            match d.datatype()? {
                Type::Null => {
                    d.null()?;
                    Ok(BenchValue::Null)
                }
                Type::Bool => Ok(BenchValue::Bool(d.bool()?)),
                Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                    let v = d.u64()?;
                    let i = i64::try_from(v).unwrap_or(i64::MAX);
                    Ok(BenchValue::Int(i))
                }
                Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::Int => {
                    Ok(BenchValue::Int(d.i64()?))
                }
                Type::Bytes => {
                    let b = d.bytes()?.to_vec();
                    Ok(BenchValue::Bytes(b))
                }
                Type::String => {
                    let s = d.str()?.to_string();
                    Ok(BenchValue::Text(s))
                }
                Type::Array => {
                    let len = d.array()?.unwrap_or(0);
                    let mut items = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        items.push(BenchValue::decode(d, ctx)?);
                    }
                    Ok(BenchValue::Array(items))
                }
                Type::Map => {
                    let len = d.map()?.unwrap_or(0);
                    let mut entries = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        let k = d.str()?.to_string();
                        let v = BenchValue::decode(d, ctx)?;
                        entries.push((k, v));
                    }
                    Ok(BenchValue::Map(entries))
                }
                _ => {
                    d.skip()?;
                    Ok(BenchValue::Null)
                }
            }
        }
    }
}
