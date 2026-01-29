use proc_macro2::TokenStream;
use quote::quote;
use syn::{GenericArgument, Ident, Path, PathArguments, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VariantKind {
    Null,
    Bool,
    Integer,
    Float,
    Bytes,
    Text,
    Array,
    Map,
}

impl VariantKind {
    pub(crate) const ORDER: [VariantKind; 8] = [
        VariantKind::Null,
        VariantKind::Bool,
        VariantKind::Integer,
        VariantKind::Float,
        VariantKind::Bytes,
        VariantKind::Text,
        VariantKind::Array,
        VariantKind::Map,
    ];

    pub(crate) fn idx(self) -> usize {
        match self {
            VariantKind::Null => 0,
            VariantKind::Bool => 1,
            VariantKind::Integer => 2,
            VariantKind::Float => 3,
            VariantKind::Bytes => 4,
            VariantKind::Text => 5,
            VariantKind::Array => 6,
            VariantKind::Map => 7,
        }
    }

    pub(crate) fn to_cbor_kind_ts(self) -> TokenStream {
        match self {
            VariantKind::Null => quote!(::sacp_cbor::CborKind::Null),
            VariantKind::Bool => quote!(::sacp_cbor::CborKind::Bool),
            VariantKind::Integer => quote!(::sacp_cbor::CborKind::Integer),
            VariantKind::Float => quote!(::sacp_cbor::CborKind::Float),
            VariantKind::Bytes => quote!(::sacp_cbor::CborKind::Bytes),
            VariantKind::Text => quote!(::sacp_cbor::CborKind::Text),
            VariantKind::Array => quote!(::sacp_cbor::CborKind::Array),
            VariantKind::Map => quote!(::sacp_cbor::CborKind::Map),
        }
    }
}

pub(crate) fn is_option_type(ty: &Type) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    seg.ident == "Option"
}

pub(crate) fn vec_inner_type(ty: &Type) -> Option<&Type> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Vec" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let mut iter = args.args.iter();
    let Some(GenericArgument::Type(inner)) = iter.next() else {
        return None;
    };
    if iter.next().is_some() {
        return None;
    }
    Some(inner)
}

pub(crate) fn type_is_ident(ty: &Type, name: &str) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    seg.ident == name
}

fn path_might_be_self(path: &Path, self_ident: &Ident) -> bool {
    let Some(last) = path.segments.last() else {
        return false;
    };
    if last.ident != *self_ident {
        return false;
    }
    if path.segments.len() == 1 {
        return true;
    }
    path.segments
        .iter()
        .take(path.segments.len() - 1)
        .all(|seg| matches!(seg.ident.to_string().as_str(), "crate" | "self" | "super"))
}

pub(crate) fn type_mentions_self(ty: &Type, self_ident: &Ident) -> bool {
    match ty {
        Type::Path(tp) => {
            if tp.qself.is_none() && path_might_be_self(&tp.path, self_ident) {
                return true;
            }
            if let Some(q) = &tp.qself {
                if type_mentions_self(&q.ty, self_ident) {
                    return true;
                }
            }
            tp.path.segments.iter().any(|seg| match &seg.arguments {
                PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
                    GenericArgument::Type(inner) => type_mentions_self(inner, self_ident),
                    _ => false,
                }),
                _ => false,
            })
        }
        Type::Reference(tr) => type_mentions_self(&tr.elem, self_ident),
        Type::Tuple(tt) => tt.elems.iter().any(|t| type_mentions_self(t, self_ident)),
        Type::Array(ta) => type_mentions_self(&ta.elem, self_ident),
        Type::Slice(ts) => type_mentions_self(&ts.elem, self_ident),
        Type::Group(tg) => type_mentions_self(&tg.elem, self_ident),
        Type::Paren(tp) => type_mentions_self(&tp.elem, self_ident),
        _ => false,
    }
}

pub(crate) fn type_kind(ty: &Type) -> Option<VariantKind> {
    match ty {
        Type::Reference(tr) => type_kind(&tr.elem),
        Type::Group(tg) => type_kind(&tg.elem),
        Type::Paren(tp) => type_kind(&tp.elem),
        Type::Slice(ts) => {
            if type_is_ident(&ts.elem, "u8") {
                Some(VariantKind::Bytes)
            } else {
                None
            }
        }
        Type::Path(tp) => {
            let seg = tp.path.segments.last()?;
            let ident = seg.ident.to_string();
            match ident.as_str() {
                "bool" => Some(VariantKind::Bool),
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" => Some(VariantKind::Integer),
                "f32" | "f64" => Some(VariantKind::Float),
                "String" | "str" => Some(VariantKind::Text),
                "CborBytesRef" => Some(VariantKind::Bytes),
                "MapEntries" => Some(VariantKind::Map),
                "Vec" => {
                    let inner = vec_inner_type(ty)?;
                    if type_is_ident(inner, "u8") {
                        Some(VariantKind::Bytes)
                    } else {
                        Some(VariantKind::Array)
                    }
                }
                "Option" | "CborValueRef" => None,
                _ => None,
            }
        }
        _ => None,
    }
}
