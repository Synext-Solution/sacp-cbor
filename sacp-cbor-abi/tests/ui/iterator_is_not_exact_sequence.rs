use core::convert::Infallible;

use sacp_cbor_abi::{projected_sequence, CborAbi, ProjectedSequence};

#[derive(CborAbi)]
#[abi(type_id = "ui.Batch", version = 1)]
struct Batch {
    #[abi(id = 1)]
    values: Vec<u64>,
}

struct IteratorBacked<'a>(&'a [u64]);

impl BatchAbiProjection for IteratorBacked<'_> {
    type Error = Infallible;
    type FieldValues<'a>
        = ProjectedSequence<core::slice::Iter<'a, u64>>
    where
        Self: 'a;

    fn values(&self) -> Result<Self::FieldValues<'_>, Self::Error> {
        Ok(projected_sequence(self.0.iter()))
    }
}

fn main() {}
