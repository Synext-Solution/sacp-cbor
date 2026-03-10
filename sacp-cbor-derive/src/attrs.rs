use proc_macro2::Span;
use syn::{spanned::Spanned, Attribute, DataEnum, Field, Fields, LitStr, Variant};

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

#[derive(Clone, Debug, Default)]
pub(crate) struct CborEnumAttr {
    pub(crate) tagging: EnumTagging,
    pub(crate) rename_all: Option<RenameRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) enum EnumTagging {
    #[default]
    External,
    Untagged,
    Internal {
        tag: LitStr,
    },
    Adjacent {
        tag: LitStr,
        content: LitStr,
    },
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

pub(crate) fn parse_cbor_enum_attrs(attrs: &[Attribute]) -> syn::Result<CborEnumAttr> {
    let mut seen_tagged = false;
    let mut seen_untagged = false;
    let mut tag: Option<LitStr> = None;
    let mut content: Option<LitStr> = None;
    let mut rename_all: Option<RenameRule> = None;

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
                "unsupported `cbor(...)` enum attribute (allowed: tagged, untagged, tag, content, rename_all)",
            ))
        })?;
    }

    if seen_tagged && seen_untagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "cbor enum cannot be both tagged and untagged",
        ));
    }

    if seen_tagged && (tag.is_some() || content.is_some()) {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(tagged)` cannot be combined with `tag` or `content`",
        ));
    }

    if seen_untagged && (tag.is_some() || content.is_some()) {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(untagged)` cannot be combined with `tag` or `content`",
        ));
    }

    if content.is_some() && tag.is_none() {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(content=...)` requires `cbor(tag=...)`",
        ));
    }

    if seen_untagged && rename_all.is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "`cbor(rename_all=...)` is meaningless for `#[cbor(untagged)]` enums",
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

    let tagging = if seen_untagged {
        EnumTagging::Untagged
    } else if let Some(tag) = tag {
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

pub(crate) fn field_key(field: &Field) -> syn::Result<LitStr> {
    let attr = parse_cbor_field_attrs(&field.attrs)?;
    let ident = field.ident.as_ref().unwrap();
    Ok(attr
        .rename
        .unwrap_or_else(|| LitStr::new(&ident.to_string(), ident.span())))
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

pub(crate) fn variant_has_rename(variant: &Variant) -> syn::Result<bool> {
    Ok(parse_cbor_variant_attrs(&variant.attrs)?.rename.is_some())
}

pub(crate) fn validate_internal_tagging(data: &DataEnum, tag: &LitStr) -> syn::Result<()> {
    for variant in &data.variants {
        match &variant.fields {
            Fields::Unnamed(_) => {
                return Err(syn::Error::new(
                    variant.span(),
                    "`#[cbor(tag = ...)]` only supports unit and struct variants; use `#[cbor(tag = ..., content = ...)]` for tuple variants",
                ));
            }
            Fields::Named(fields) => {
                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    if attr.skip {
                        continue;
                    }

                    let key = field_key(field)?;
                    if key.value() == tag.value() {
                        return Err(syn::Error::new(
                            field.span(),
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
