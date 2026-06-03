use quote::{format_ident, quote, ToTokens};
use syn::{spanned::Spanned, DataEnum, DataStruct, Fields, Generics, Ident, LitStr, Path, Type};

use crate::schema::{
    cbor_text_key_bytes, enum_variants, generic_type_params, internal_tagged_tuple_variant_error,
    named_fields, tuple_fields, type_needs_trait_bound, validate_internal_tagging,
    CborContainerAttr, EnumTagging, NamedFieldSpec, TupleFieldSpec, VariantSpec,
};
use crate::util::add_where_bounds;

struct SortedMapEntry {
    key_bytes: Vec<u8>,
    entry: proc_macro2::TokenStream,
}

fn sort_entries(mut entries: Vec<SortedMapEntry>) -> Vec<proc_macro2::TokenStream> {
    entries.sort_by(|a, b| {
        a.key_bytes
            .len()
            .cmp(&b.key_bytes.len())
            .then_with(|| a.key_bytes.cmp(&b.key_bytes))
    });

    entries.into_iter().map(|entry| entry.entry).collect()
}

fn entries_into_tokens(entries: Vec<SortedMapEntry>) -> Vec<proc_macro2::TokenStream> {
    entries.into_iter().map(|entry| entry.entry).collect()
}

fn map_entry(key: &LitStr, entry: proc_macro2::TokenStream) -> SortedMapEntry {
    SortedMapEntry {
        key_bytes: cbor_text_key_bytes(key),
        entry,
    }
}

fn encode_impl(
    crate_path: &Path,
    name: &Ident,
    impl_generics: impl ToTokens,
    ty_generics: impl ToTokens,
    where_clause: impl ToTokens,
    body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        impl #impl_generics #crate_path::CborEncode for #name #ty_generics #where_clause {
            fn encode(&self, enc: &mut #crate_path::Encoder) -> ::core::result::Result<(), #crate_path::CborError> {
                #body
            }
        }
    }
}

fn encode_match_impl(
    crate_path: &Path,
    name: &Ident,
    impl_generics: impl ToTokens,
    ty_generics: impl ToTokens,
    where_clause: impl ToTokens,
    arms: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    encode_impl(
        crate_path,
        name,
        impl_generics,
        ty_generics,
        where_clause,
        quote! { match self { #(#arms),* } },
    )
}

fn finish_encode_match_impl<'a>(
    crate_path: &Path,
    name: &Ident,
    impl_generics: impl ToTokens,
    ty_generics: impl ToTokens,
    base_where_clause: Option<&syn::WhereClause>,
    bounds: impl IntoIterator<Item = &'a Type>,
    arms: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    let encode_where_clause =
        add_where_bounds(base_where_clause, bounds, quote!(#crate_path::CborEncode));
    encode_match_impl(
        crate_path,
        name,
        impl_generics,
        ty_generics,
        encode_where_clause,
        arms,
    )
}

struct EncodeImplParts<'a> {
    crate_path: &'a Path,
    generics: &'a Generics,
    base_where_clause: Option<&'a syn::WhereClause>,
}

impl<'a> EncodeImplParts<'a> {
    fn new(crate_path: &'a Path, generics: &'a Generics) -> Self {
        let (_, _, base_where_clause) = generics.split_for_impl();
        Self {
            crate_path,
            generics,
            base_where_clause,
        }
    }

    fn finish_match<'b>(
        &self,
        name: &Ident,
        bounds: impl IntoIterator<Item = &'b Type>,
        arms: &[proc_macro2::TokenStream],
    ) -> proc_macro2::TokenStream {
        let (impl_generics, ty_generics, _) = self.generics.split_for_impl();
        finish_encode_match_impl(
            self.crate_path,
            name,
            impl_generics,
            ty_generics,
            self.base_where_clause,
            bounds,
            arms,
        )
    }
}

fn named_entries_with_pats<'a, F>(
    crate_path: &Path,
    name: &Ident,
    type_params: &[Ident],
    fields: &[NamedFieldSpec<'a>],
    bounds: &mut Vec<&'a Type>,
    value: F,
) -> syn::Result<(Vec<proc_macro2::TokenStream>, Vec<SortedMapEntry>)>
where
    F: Fn(&Ident) -> proc_macro2::TokenStream,
{
    let mut pats = Vec::new();
    let mut entries = Vec::new();

    for field in fields {
        let f_ident = field.ident;
        let Some(key) = field.wire_key.as_ref() else {
            pats.push(quote! { #f_ident: _ });
            continue;
        };
        pats.push(quote! { #f_ident });

        if type_needs_trait_bound(field.ty, name, type_params) {
            bounds.push(field.ty);
        }

        let value_ts = value(f_ident);
        entries.push(map_entry(
            key,
            quote! {
                m.entry(#key, |enc| #crate_path::CborEncode::encode(#value_ts, enc))?;
            },
        ));
    }

    Ok((pats, entries))
}

fn tuple_variant_parts<'a>(
    crate_path: &Path,
    name: &Ident,
    type_params: &[Ident],
    fields: &[TupleFieldSpec<'a>],
    bounds: &mut Vec<&'a Type>,
) -> syn::Result<(Vec<Ident>, Vec<proc_macro2::TokenStream>)> {
    let mut pats = Vec::new();
    let mut items = Vec::new();

    for field in fields {
        let idx = field.index;
        let var = format_ident!("v{idx}");
        pats.push(var.clone());

        if type_needs_trait_bound(field.ty, name, type_params) {
            bounds.push(field.ty);
        }
        items.push(quote! { #crate_path::CborEncode::encode_array_item(#var, a)?; });
    }

    Ok((pats, items))
}

pub(crate) fn encode_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
    attrs: &CborContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let crate_path = &attrs.crate_path;
    let type_params = generic_type_params(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    match &data.fields {
        Fields::Named(fields) => {
            let mut bounds = Vec::new();
            let field_specs = named_fields(fields)?;

            let (_, entries) = named_entries_with_pats(
                crate_path,
                name,
                &type_params,
                &field_specs,
                &mut bounds,
                |ident| quote!(&self.#ident),
            )?;
            let entries = entries_into_tokens(entries);

            let len = entries.len();
            let encode_where_clause =
                add_where_bounds(base_where_clause, bounds, quote!(#crate_path::CborEncode));

            Ok(encode_impl(
                crate_path,
                name,
                impl_generics,
                ty_generics,
                encode_where_clause,
                quote! {
                    enc.map(#len, |m| {
                        #(#entries)*
                        Ok(())
                    })
                },
            ))
        }

        Fields::Unnamed(fields) => {
            let mut items = Vec::new();
            let mut bounds = Vec::new();

            for field in tuple_fields(fields, "tuple struct fields")? {
                let idx = field.index;
                let index = syn::Index::from(idx);

                if type_needs_trait_bound(field.ty, name, &type_params) {
                    bounds.push(field.ty);
                }

                items.push(quote! {
                    #crate_path::CborEncode::encode_array_item(&self.#index, a)?;
                });
            }

            let len = items.len();
            let encode_where_clause =
                add_where_bounds(base_where_clause, bounds, quote!(#crate_path::CborEncode));

            Ok(encode_impl(
                crate_path,
                name,
                impl_generics,
                ty_generics,
                encode_where_clause,
                quote! {
                    enc.array(#len, |a| {
                        #(#items)*
                        Ok(())
                    })
                },
            ))
        }

        Fields::Unit => Ok(encode_impl(
            crate_path,
            name,
            impl_generics,
            ty_generics,
            base_where_clause,
            quote! { enc.null() },
        )),
    }
}

pub(crate) fn encode_enum(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &CborContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let variants = enum_variants(data, attrs.rename_all)?;
    let type_params = generic_type_params(generics);
    match &attrs.tagging {
        EnumTagging::External => {
            encode_enum_external(&attrs.crate_path, name, generics, &type_params, &variants)
        }
        EnumTagging::Internal { tag } => encode_enum_internal(
            &attrs.crate_path,
            name,
            generics,
            &type_params,
            data,
            &variants,
            tag,
        ),
        EnumTagging::Adjacent { tag, content } => encode_enum_adjacent(
            &attrs.crate_path,
            name,
            generics,
            &type_params,
            &variants,
            tag,
            content,
        ),
    }
}

fn encode_enum_external(
    crate_path: &Path,
    name: &Ident,
    generics: &Generics,
    type_params: &[Ident],
    variants: &[VariantSpec<'_>],
) -> syn::Result<proc_macro2::TokenStream> {
    let impl_parts = EncodeImplParts::new(crate_path, generics);

    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in variants {
        let vname = &variant.name;
        let ident = variant.ident;

        match variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#ident => enc.map(1, |m| {
                        m.entry(#vname, #crate_path::Encoder::null)?;
                        Ok(())
                    })
                });
            }

            Fields::Unnamed(fields) => {
                let field_specs = tuple_fields(fields, "tuple enum variant fields")?;
                let (pats, items) =
                    tuple_variant_parts(crate_path, name, type_params, &field_specs, &mut bounds)?;

                let len = items.len();
                if len == 1 {
                    let value = &pats[0];
                    arms.push(quote! {
                        Self::#ident( #(#pats),* ) => enc.map(1, |m| {
                            m.entry(#vname, |enc| #crate_path::CborEncode::encode(#value, enc))?;
                            Ok(())
                        })
                    });
                } else {
                    arms.push(quote! {
                        Self::#ident( #(#pats),* ) => enc.map(1, |m| {
                            m.entry(#vname, |enc| {
                                enc.array(#len, |a| {
                                    #(#items)*
                                    Ok(())
                                })
                            })?;
                            Ok(())
                        })
                    });
                }
            }

            Fields::Named(fields) => {
                let field_specs = named_fields(fields)?;
                let (pats, entries) = named_entries_with_pats(
                    crate_path,
                    name,
                    type_params,
                    &field_specs,
                    &mut bounds,
                    |ident| quote!(#ident),
                )?;
                let entries = entries_into_tokens(entries);

                let len = entries.len();
                arms.push(quote! {
                    Self::#ident { #(#pats),* } => enc.map(1, |m| {
                        m.entry(#vname, |enc| {
                            enc.map(#len, |m| {
                                #(#entries)*
                                Ok(())
                            })
                        })?;
                        Ok(())
                    })
                });
            }
        }
    }

    Ok(impl_parts.finish_match(name, bounds, &arms))
}

fn encode_enum_internal(
    crate_path: &Path,
    name: &Ident,
    generics: &Generics,
    type_params: &[Ident],
    data: &DataEnum,
    variants: &[VariantSpec<'_>],
    tag: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    validate_internal_tagging(data, tag)?;

    let impl_parts = EncodeImplParts::new(crate_path, generics);

    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in variants {
        let vname = &variant.name;
        let ident = variant.ident;

        match variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#ident => enc.map(1, |m| {
                        m.entry(#tag, |enc| #crate_path::CborEncode::encode(&#vname, enc))?;
                        Ok(())
                    })
                });
            }
            Fields::Named(fields) => {
                let field_specs = named_fields(fields)?;
                let (pats, mut entries) = named_entries_with_pats(
                    crate_path,
                    name,
                    type_params,
                    &field_specs,
                    &mut bounds,
                    |ident| quote!(#ident),
                )?;
                entries.push(map_entry(
                    tag,
                    quote! {
                        m.entry(#tag, |enc| #crate_path::CborEncode::encode(&#vname, enc))?;
                    },
                ));
                let entries = sort_entries(entries);
                let len = entries.len();

                arms.push(quote! {
                    Self::#ident { #(#pats),* } => enc.map(#len, |m| {
                        #(#entries)*
                        Ok(())
                    })
                });
            }
            Fields::Unnamed(fields) => {
                return Err(internal_tagged_tuple_variant_error(fields.span()))
            }
        }
    }

    Ok(impl_parts.finish_match(name, bounds, &arms))
}

fn encode_enum_adjacent(
    crate_path: &Path,
    name: &Ident,
    generics: &Generics,
    type_params: &[Ident],
    variants: &[VariantSpec<'_>],
    tag: &LitStr,
    content: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    let impl_parts = EncodeImplParts::new(crate_path, generics);

    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in variants {
        let vname = &variant.name;
        let ident = variant.ident;

        match variant.fields {
            Fields::Unit => {
                let entries = sort_entries(vec![
                    map_entry(
                        tag,
                        quote! {
                            m.entry(#tag, |enc| #crate_path::CborEncode::encode(&#vname, enc))?;
                        },
                    ),
                    map_entry(
                        content,
                        quote! {
                            m.entry(#content, #crate_path::Encoder::null)?;
                        },
                    ),
                ]);
                arms.push(quote! {
                    Self::#ident => enc.map(2, |m| {
                        #(#entries)*
                        Ok(())
                    })
                });
            }
            Fields::Unnamed(fields) => {
                let field_specs = tuple_fields(fields, "tuple enum variant fields")?;
                let (pats, items) =
                    tuple_variant_parts(crate_path, name, type_params, &field_specs, &mut bounds)?;
                let len = items.len();
                let content_entry = if len == 1 {
                    let value = &pats[0];
                    map_entry(
                        content,
                        quote! {
                            m.entry(#content, |enc| #crate_path::CborEncode::encode(#value, enc))?;
                        },
                    )
                } else {
                    map_entry(
                        content,
                        quote! {
                            m.entry(#content, |enc| {
                                enc.array(#len, |a| {
                                    #(#items)*
                                    Ok(())
                                })
                            })?;
                        },
                    )
                };

                let entries = sort_entries(vec![
                    map_entry(
                        tag,
                        quote! {
                            m.entry(#tag, |enc| #crate_path::CborEncode::encode(&#vname, enc))?;
                        },
                    ),
                    content_entry,
                ]);

                arms.push(quote! {
                    Self::#ident( #(#pats),* ) => enc.map(2, |m| {
                        #(#entries)*
                        Ok(())
                    })
                });
            }
            Fields::Named(fields) => {
                let field_specs = named_fields(fields)?;
                let (pats, entries) = named_entries_with_pats(
                    crate_path,
                    name,
                    type_params,
                    &field_specs,
                    &mut bounds,
                    |ident| quote!(#ident),
                )?;
                let entries = entries_into_tokens(entries);
                let len = entries.len();
                let top_entries = sort_entries(vec![
                    map_entry(
                        tag,
                        quote! {
                            m.entry(#tag, |enc| #crate_path::CborEncode::encode(&#vname, enc))?;
                        },
                    ),
                    map_entry(
                        content,
                        quote! {
                            m.entry(#content, |enc| {
                                enc.map(#len, |m| {
                                    #(#entries)*
                                    Ok(())
                                })
                            })?;
                        },
                    ),
                ]);

                arms.push(quote! {
                    Self::#ident { #(#pats),* } => enc.map(2, |m| {
                        #(#top_entries)*
                        Ok(())
                    })
                });
            }
        }
    }

    Ok(impl_parts.finish_match(name, bounds, &arms))
}
