use proc_macro2::Span;
use syn::{spanned::Spanned, Attribute, LitStr};

#[derive(Default, Clone)]
pub(crate) struct CborFieldAttr {
    pub(crate) rename: Option<LitStr>,
    pub(crate) skip: bool,
    pub(crate) default: bool,
}

#[derive(Default, Clone)]
pub(crate) struct CborVariantAttr {
    pub(crate) rename: Option<LitStr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum EnumTagging {
    #[default]
    Tagged,
    Untagged,
}

pub(crate) fn ensure_no_cbor_attrs(attrs: &[Attribute], ctx: &str) -> syn::Result<()> {
    for a in attrs {
        if a.path().is_ident("cbor") {
            return Err(syn::Error::new(
                a.span(),
                format!("`#[cbor(...)]` is not supported on {ctx}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_cbor_field_attrs(attrs: &[Attribute]) -> syn::Result<CborFieldAttr> {
    let mut out = CborFieldAttr::default();
    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                if out.skip {
                    return Err(meta.error("duplicate `cbor(skip)`"));
                }
                out.skip = true;
                return Ok(());
            }
            if meta.path.is_ident("default") {
                if out.default {
                    return Err(meta.error("duplicate `cbor(default)`"));
                }
                out.default = true;
                return Ok(());
            }
            if meta.path.is_ident("rename") {
                if out.rename.is_some() {
                    return Err(meta.error("duplicate `cbor(rename=...)`"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit);
                return Ok(());
            }
            Err(meta
                .error("unsupported `cbor(...)` field attribute (allowed: rename, skip, default)"))
        })?;
    }

    if out.skip && (out.rename.is_some() || out.default) {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(skip)` cannot be combined with `rename` or `default`",
        ));
    }

    Ok(out)
}

pub(crate) fn parse_cbor_variant_attrs(attrs: &[Attribute]) -> syn::Result<CborVariantAttr> {
    let mut out = CborVariantAttr::default();
    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                if out.rename.is_some() {
                    return Err(meta.error("duplicate `cbor(rename=...)` on variant"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit);
                return Ok(());
            }
            if meta.path.is_ident("skip") || meta.path.is_ident("default") {
                return Err(
                    meta.error("`cbor(skip)` / `cbor(default)` are not valid on enum variants")
                );
            }
            Err(meta.error("unsupported `cbor(...)` variant attribute (allowed: rename)"))
        })?;
    }
    Ok(out)
}

pub(crate) fn parse_cbor_enum_attrs(attrs: &[Attribute]) -> syn::Result<EnumTagging> {
    let mut seen_tagged = false;
    let mut seen_untagged = false;

    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("untagged") {
                if seen_untagged {
                    return Err(meta.error("duplicate `cbor(untagged)`"));
                }
                seen_untagged = true;
                return Ok(());
            }
            if meta.path.is_ident("tagged") {
                if seen_tagged {
                    return Err(meta.error("duplicate `cbor(tagged)`"));
                }
                seen_tagged = true;
                return Ok(());
            }
            Err(meta.error("unsupported `cbor(...)` enum attribute (allowed: tagged, untagged)"))
        })?;
    }

    if seen_tagged && seen_untagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "cbor enum cannot be both tagged and untagged",
        ));
    }

    Ok(if seen_untagged {
        EnumTagging::Untagged
    } else {
        EnumTagging::Tagged
    })
}
