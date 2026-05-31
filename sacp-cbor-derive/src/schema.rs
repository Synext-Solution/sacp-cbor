use core::cmp::Ordering;
use proc_macro2::Span;
use syn::{
    spanned::Spanned, Attribute, DataEnum, Field, Fields, FieldsNamed, FieldsUnnamed,
    GenericArgument, Ident, LitStr, Path, PathArguments, Type, Variant,
};

#[derive(Default, Clone)]
pub(crate) struct CborFieldAttr {
    pub(crate) rename: Option<LitStr>,
    pub(crate) skip: bool,
}

#[derive(Default, Clone)]
pub(crate) struct CborVariantAttr {
    pub(crate) rename: Option<LitStr>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CborEnumAttr {
    pub(crate) tagging: EnumTagging,
    pub(crate) rename_all: Option<RenameRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) enum EnumTagging {
    #[default]
    External,
    Internal {
        tag: LitStr,
    },
    Adjacent {
        tag: LitStr,
        content: LitStr,
    },
}

pub(crate) struct NamedFieldSpec<'a> {
    pub(crate) field: &'a Field,
    pub(crate) ident: &'a Ident,
    pub(crate) ty: &'a Type,
    pub(crate) wire_key: Option<LitStr>,
}

pub(crate) struct TupleFieldSpec<'a> {
    pub(crate) ty: &'a Type,
    pub(crate) index: usize,
}

pub(crate) struct VariantSpec<'a> {
    pub(crate) ident: &'a Ident,
    pub(crate) fields: &'a Fields,
    pub(crate) name: LitStr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenameRule {
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl RenameRule {
    fn parse(lit: &LitStr) -> syn::Result<Self> {
        match lit.value().as_str() {
            "lowercase" => Ok(Self::Lower),
            "UPPERCASE" => Ok(Self::Upper),
            "PascalCase" => Ok(Self::Pascal),
            "camelCase" => Ok(Self::Camel),
            "snake_case" => Ok(Self::Snake),
            "SCREAMING_SNAKE_CASE" => Ok(Self::ScreamingSnake),
            "kebab-case" => Ok(Self::Kebab),
            "SCREAMING-KEBAB-CASE" => Ok(Self::ScreamingKebab),
            _ => Err(syn::Error::new(
                lit.span(),
                "unsupported `cbor(rename_all=...)` rule",
            )),
        }
    }

    pub(crate) fn apply_to_variant(self, value: &str) -> String {
        let words = split_words(value);
        match self {
            Self::Lower => words
                .iter()
                .map(|word| lowercase(word))
                .collect::<Vec<_>>()
                .join(""),
            Self::Upper => words
                .iter()
                .map(|word| uppercase(word))
                .collect::<Vec<_>>()
                .join(""),
            Self::Pascal => words
                .iter()
                .map(|word| capitalize(word))
                .collect::<Vec<_>>()
                .join(""),
            Self::Camel => {
                let mut out = String::new();
                for (idx, word) in words.iter().enumerate() {
                    if idx == 0 {
                        out.push_str(&lowercase(word));
                    } else {
                        out.push_str(&capitalize(word));
                    }
                }
                out
            }
            Self::Snake => words
                .iter()
                .map(|word| lowercase(word))
                .collect::<Vec<_>>()
                .join("_"),
            Self::ScreamingSnake => words
                .iter()
                .map(|word| uppercase(word))
                .collect::<Vec<_>>()
                .join("_"),
            Self::Kebab => words
                .iter()
                .map(|word| lowercase(word))
                .collect::<Vec<_>>()
                .join("-"),
            Self::ScreamingKebab => words
                .iter()
                .map(|word| uppercase(word))
                .collect::<Vec<_>>()
                .join("-"),
        }
    }
}

fn lowercase(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

fn uppercase(value: &str) -> String {
    value.chars().flat_map(char::to_uppercase).collect()
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };

    let mut out = String::new();
    out.extend(first.to_uppercase());
    out.push_str(&lowercase(chars.as_str()));
    out
}

fn split_words(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();

    for (idx, &ch) in chars.iter().enumerate() {
        if matches!(ch, '_' | '-') {
            if !current.is_empty() {
                words.push(core::mem::take(&mut current));
            }
            continue;
        }

        let boundary = if let Some(prev) = current.chars().last() {
            let next = chars.get(idx + 1).copied();
            (prev.is_lowercase() && ch.is_uppercase())
                || (prev.is_ascii_digit() && ch.is_alphabetic())
                || (prev.is_alphabetic() && ch.is_ascii_digit())
                || (prev.is_uppercase()
                    && ch.is_uppercase()
                    && next.is_some_and(char::is_lowercase))
        } else {
            false
        };

        if boundary && !current.is_empty() {
            words.push(core::mem::take(&mut current));
        }

        current.push(ch);
    }

    if !current.is_empty() {
        words.push(current);
    }

    if words.is_empty() {
        words.push(String::new());
    }

    words
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

fn type_mentions_self(ty: &Type, self_ident: &Ident) -> bool {
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

pub(crate) fn type_needs_trait_bound(ty: &Type, self_ident: &Ident) -> bool {
    !type_mentions_self(ty, self_ident)
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
                return Err(meta.error("`cbor(default)` is not part of the exact schema derive"));
            }
            if meta.path.is_ident("rename") {
                if out.rename.is_some() {
                    return Err(meta.error("duplicate `cbor(rename=...)`"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit);
                return Ok(());
            }
            Err(meta.error("unsupported `cbor(...)` field attribute (allowed: rename, skip)"))
        })?;
    }

    if out.skip && out.rename.is_some() {
        let span = out.rename.as_ref().map_or(Span::call_site(), LitStr::span);
        return Err(syn::Error::new(
            span,
            "`cbor(skip)` cannot be combined with `rename`",
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
                    meta.error("`cbor(skip)` and `cbor(default)` are not valid on enum variants")
                );
            }
            Err(meta.error("unsupported `cbor(...)` variant attribute (allowed: rename)"))
        })?;
    }
    Ok(out)
}

pub(crate) fn parse_cbor_enum_attrs(attrs: &[Attribute]) -> syn::Result<CborEnumAttr> {
    let mut seen_tagged = false;
    let mut tag: Option<LitStr> = None;
    let mut content: Option<LitStr> = None;
    let mut rename_all: Option<RenameRule> = None;

    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("untagged") {
                return Err(meta.error("`cbor(untagged)` is not part of the exact schema derive"));
            }
            if meta.path.is_ident("tagged") {
                if seen_tagged {
                    return Err(meta.error("duplicate `cbor(tagged)`"));
                }
                seen_tagged = true;
                return Ok(());
            }
            if meta.path.is_ident("tag") {
                if tag.is_some() {
                    return Err(meta.error("duplicate `cbor(tag=...)`"));
                }
                tag = Some(meta.value()?.parse()?);
                return Ok(());
            }
            if meta.path.is_ident("content") {
                if content.is_some() {
                    return Err(meta.error("duplicate `cbor(content=...)`"));
                }
                content = Some(meta.value()?.parse()?);
                return Ok(());
            }
            if meta.path.is_ident("rename_all") {
                if rename_all.is_some() {
                    return Err(meta.error("duplicate `cbor(rename_all=...)`"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                rename_all = Some(RenameRule::parse(&lit)?);
                return Ok(());
            }
            Err(meta.error(
                "unsupported `cbor(...)` enum attribute (allowed: tagged, tag, content, rename_all)",
            ))
        })?;
    }

    if seen_tagged && (tag.is_some() || content.is_some()) {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(tagged)` cannot be combined with `tag` or `content`",
        ));
    }

    if content.is_some() && tag.is_none() {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(content=...)` requires `cbor(tag=...)`",
        ));
    }

    if let (Some(tag_lit), Some(content_lit)) = (&tag, &content) {
        if tag_lit.value() == content_lit.value() {
            return Err(syn::Error::new(
                content_lit.span(),
                "`cbor(tag=..., content=...)` must use distinct field names",
            ));
        }
    }

    let tagging = if let Some(tag) = tag {
        if let Some(content) = content {
            EnumTagging::Adjacent { tag, content }
        } else {
            EnumTagging::Internal { tag }
        }
    } else {
        EnumTagging::External
    };

    Ok(CborEnumAttr {
        tagging,
        rename_all,
    })
}

pub(crate) fn named_field_ident(field: &Field) -> syn::Result<&syn::Ident> {
    field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new(field.span(), "expected a named field"))
}

pub(crate) fn named_fields(fields: &FieldsNamed) -> syn::Result<Vec<NamedFieldSpec<'_>>> {
    let mut seen = Vec::<String>::new();
    let mut out = Vec::new();
    for field in &fields.named {
        let attr = parse_cbor_field_attrs(&field.attrs)?;
        let ident = named_field_ident(field)?;
        let wire_key = if attr.skip {
            None
        } else {
            Some(
                attr.rename
                    .unwrap_or_else(|| LitStr::new(&ident.to_string(), ident.span())),
            )
        };

        if let Some(key) = &wire_key {
            let value = key.value();
            if seen.iter().any(|existing| existing == &value) {
                return Err(syn::Error::new(
                    key.span(),
                    format!("duplicate CBOR field key `{value}`"),
                ));
            }
            seen.push(value);
        }

        out.push(NamedFieldSpec {
            field,
            ident,
            ty: &field.ty,
            wire_key,
        });
    }
    out.sort_by(|a, b| match (&a.wire_key, &b.wire_key) {
        (Some(a), Some(b)) => cmp_field_keys(a, b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });

    Ok(out)
}

pub(crate) fn cmp_field_keys(a: &LitStr, b: &LitStr) -> Ordering {
    let a = cbor_text_key_bytes(a);
    let b = cbor_text_key_bytes(b);
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(&b),
        other => other,
    }
}

pub(crate) fn cbor_text_key_bytes(key: &LitStr) -> Vec<u8> {
    let text = key.value();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len + 9);

    if len < 24 {
        out.push(0x60 | (len as u8));
    } else if let Ok(len) = u8::try_from(len) {
        out.extend_from_slice(&[0x78, len]);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0x79);
        out.extend_from_slice(&len.to_be_bytes());
    } else if let Ok(len) = u32::try_from(len) {
        out.push(0x7a);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = len as u64;
        out.push(0x7b);
        out.extend_from_slice(&len.to_be_bytes());
    }

    out.extend_from_slice(bytes);
    out
}

pub(crate) fn tuple_fields<'a>(
    fields: &'a FieldsUnnamed,
    ctx: &str,
) -> syn::Result<Vec<TupleFieldSpec<'a>>> {
    let mut out = Vec::new();
    for (index, field) in fields.unnamed.iter().enumerate() {
        ensure_no_cbor_attrs(&field.attrs, ctx)?;
        out.push(TupleFieldSpec {
            ty: &field.ty,
            index,
        });
    }
    Ok(out)
}

pub(crate) fn enum_variants(
    data: &DataEnum,
    rename_all: Option<RenameRule>,
) -> syn::Result<Vec<VariantSpec<'_>>> {
    let mut seen = Vec::<String>::new();
    let mut out = Vec::new();
    for variant in &data.variants {
        let name = variant_name(variant, rename_all)?;
        let value = name.value();
        if seen.iter().any(|existing| existing == &value) {
            return Err(syn::Error::new(
                name.span(),
                format!("duplicate CBOR variant name `{value}`"),
            ));
        }
        seen.push(value);
        out.push(VariantSpec {
            ident: &variant.ident,
            fields: &variant.fields,
            name,
        });
    }
    Ok(out)
}

pub(crate) fn variant_name(
    variant: &Variant,
    rename_all: Option<RenameRule>,
) -> syn::Result<LitStr> {
    let attr = parse_cbor_variant_attrs(&variant.attrs)?;
    if let Some(rename) = attr.rename {
        return Ok(rename);
    }

    let name = if let Some(rule) = rename_all {
        rule.apply_to_variant(&variant.ident.to_string())
    } else {
        variant.ident.to_string()
    };

    Ok(LitStr::new(&name, variant.ident.span()))
}

pub(crate) fn validate_internal_tagging(data: &DataEnum, tag: &LitStr) -> syn::Result<()> {
    for variant in &data.variants {
        match &variant.fields {
            Fields::Unnamed(_) => {
                return Err(internal_tagged_tuple_variant_error(variant.span()));
            }
            Fields::Named(fields) => {
                for field in named_fields(fields)? {
                    let Some(key) = field.wire_key else {
                        continue;
                    };
                    if key.value() == tag.value() {
                        return Err(syn::Error::new(
                            field.field.span(),
                            format!(
                                "field key `{}` conflicts with internal enum tag `{}`",
                                key.value(),
                                tag.value()
                            ),
                        ));
                    }
                }
            }
            Fields::Unit => {}
        }
    }
    Ok(())
}

pub(crate) fn internal_tagged_tuple_variant_error(span: Span) -> syn::Error {
    syn::Error::new(
        span,
        "`#[cbor(tag = ...)]` only supports unit and struct variants; use `#[cbor(tag = ..., content = ...)]` for tuple variants",
    )
}
