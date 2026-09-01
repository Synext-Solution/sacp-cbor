use quote::{format_ident, quote};
use syn::{Generics, Ident, Lifetime, Visibility};

use crate::{
    storage_ident, ty_generics_with_lifetime, view_type, ContainerAttr, FieldSetSpec,
    TransparentInner, UnknownFieldMode, UnknownVariantMode, VariantSpec,
};
pub(crate) fn derive_struct_view(
    vis: &Visibility,
    name: &Ident,
    generics: &Generics,
    field_set: &FieldSetSpec<'_>,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let view_name = format_ident!("{name}View");
    let view_lifetime: Lifetime = syn::parse_quote!('__sacp_view);
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let view_ty_generics = ty_generics_with_lifetime(generics, &view_lifetime);
    let self_ty = quote!(#name #view_ty_generics);
    let to_owned = quote! {
        #[inline]
        pub fn to_owned<__C>(
            &self,
            context: &mut __C,
        ) -> ::core::result::Result<#self_ty, __C::Error>
        where
            __C: #abi_path::AbiDecodeContext + ?Sized,
        {
            let __abi_canon = self.raw.as_canonical_ref();
            #abi_path::decode_canonical(__abi_canon, context)
        }
    };

    let tokens = field_set_view_tokens(
        vis,
        &view_name,
        field_set,
        attrs.unknown_fields,
        attrs,
        Some(to_owned),
    );
    Ok(quote! {
        #tokens

        impl<'__sacp_view> #abi_path::AbiViewField<'__sacp_view>
            for #name #view_ty_generics
        {
            type View = #view_name<'__sacp_view>;

            #[inline]
            fn view_field(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self::View, #cbor_path::CborError> {
                <#view_name<'__sacp_view> as #abi_path::AbiView<'__sacp_view>>::view_from_value(
                    value,
                )
            }
        }
    })
}

pub(crate) fn derive_transparent_struct_view(
    vis: &Visibility,
    name: &Ident,
    generics: &Generics,
    inner: &TransparentInner<'_>,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let view_name = format_ident!("{name}View");
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let view_lifetime: Lifetime = syn::parse_quote!('__sacp_view);
    let view_ty_generics = ty_generics_with_lifetime(generics, &view_lifetime);
    let self_ty = quote!(#name #view_ty_generics);
    let inner_ty = view_type(inner.ty, &view_lifetime);
    let validate_invariants = quote! {
        let _ = <#inner_ty as #abi_path::AbiViewField<'__sacp_view>>::view_field(value)?;
    };

    Ok(quote! {
        #[derive(Debug, Clone, Copy)]
        #vis struct #view_name<'__sacp_view> {
            raw: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
        }

        impl<'__sacp_view> #view_name<'__sacp_view> {
            #[inline]
            pub fn from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_canonical(cbor)
            }

            #[inline]
            pub fn from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_value(value)
            }

            #[inline]
            pub fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }

            #[inline]
            pub fn inner(
                &self,
            ) -> ::core::result::Result<
                <#inner_ty as #abi_path::AbiViewField<'__sacp_view>>::View,
                #cbor_path::CborError,
            > {
                <#inner_ty as #abi_path::AbiViewField<'__sacp_view>>::view_field(self.raw)
            }

            #[inline]
            pub fn to_owned<__C>(
                &self,
                context: &mut __C,
            ) -> ::core::result::Result<#self_ty, __C::Error>
            where
                __C: #abi_path::AbiDecodeContext + ?Sized,
            {
                let __abi_canon = self.raw.as_canonical_ref();
                #abi_path::decode_canonical(__abi_canon, context)
            }
        }

        impl<'__sacp_view> #abi_path::AbiView<'__sacp_view> for #view_name<'__sacp_view> {
            #[inline]
            fn view_from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                Self::view_from_value(cbor.root())
            }

            #[inline]
            fn view_from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                #validate_invariants
                ::core::result::Result::Ok(Self { raw: value })
            }

            #[inline]
            fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }
        }

        impl<'__sacp_view> #abi_path::AbiViewField<'__sacp_view>
            for #name #view_ty_generics
        {
            type View = #view_name<'__sacp_view>;

            #[inline]
            fn view_field(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self::View, #cbor_path::CborError> {
                <#view_name<'__sacp_view> as #abi_path::AbiView<'__sacp_view>>::view_from_value(
                    value,
                )
            }
        }
    })
}

fn field_set_view_tokens(
    vis: &Visibility,
    view_name: &Ident,
    field_set: &FieldSetSpec<'_>,
    unknown_mode: UnknownFieldMode,
    attrs: &ContainerAttr,
    extra_methods: Option<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let view_lifetime: Lifetime = syn::parse_quote!('__sacp_view);

    let storage_fields = field_set.fields.iter().map(|field| {
        let storage = storage_ident(field.ident);
        quote! {
            #storage: ::core::option::Option<
                #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>
            >,
        }
    });
    let storage_decls = field_set.fields.iter().map(|field| {
        let storage = storage_ident(field.ident);
        quote! {
            let mut #storage: ::core::option::Option<
                #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>
            > = ::core::option::Option::None;
        }
    });
    let match_arms = field_set.fields.iter().map(|field| {
        let id = field.id;
        let storage = storage_ident(field.ident);
        quote! { #id => #storage = ::core::option::Option::Some(__abi_entry.value), }
    });
    let unknown_arm = match unknown_mode {
        UnknownFieldMode::Reject => quote! {
            _ => {
                return Err(#cbor_path::CborError::new(
                    #cbor_path::ErrorCode::UnknownField,
                    __abi_entry.id_offset,
                ));
            }
        },
        UnknownFieldMode::Ignore | UnknownFieldMode::Preserve => quote! { _ => {} },
    };
    let required_checks = field_set
        .fields
        .iter()
        .filter(|field| !field.optional)
        .map(|field| {
            let storage = storage_ident(field.ident);
            quote! {
                if #storage.is_none() {
                    return Err(#cbor_path::CborError::new(
                        #cbor_path::ErrorCode::MissingKey,
                        value.offset(),
                    ));
                }
            }
        });
    let construct_fields = field_set.fields.iter().map(|field| {
        let storage = storage_ident(field.ident);
        quote! { #storage, }
    });

    let accessors = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let raw_ident = format_ident!("{ident}_raw");
        let storage = storage_ident(field.ident);
        let wire_ty = view_type(field.wire_ty, &view_lifetime);
        if field.optional {
            quote! {
                #[inline]
                pub fn #raw_ident(
                    &self,
                ) -> ::core::result::Result<
                    ::core::option::Option<
                        #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>
                    >,
                    #cbor_path::CborError,
                > {
                    ::core::result::Result::Ok(self.#storage)
                }

                #[inline]
                pub fn #ident(
                    &self,
                ) -> ::core::result::Result<
                    ::core::option::Option<
                        <#wire_ty as #abi_path::AbiViewField<'__sacp_view>>::View
                    >,
                    #cbor_path::CborError,
                > {
                    self.#storage
                        .map(<#wire_ty as #abi_path::AbiViewField<'__sacp_view>>::view_field)
                        .transpose()
                }
            }
        } else {
            quote! {
                #[inline]
                pub fn #raw_ident(
                    &self,
                ) -> ::core::result::Result<
                    #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
                    #cbor_path::CborError,
                > {
                    self.#storage.ok_or_else(|| {
                        #cbor_path::CborError::new(
                            #cbor_path::ErrorCode::MissingKey,
                            self.raw.offset(),
                        )
                    })
                }

                #[inline]
                pub fn #ident(
                    &self,
                ) -> ::core::result::Result<
                    <#wire_ty as #abi_path::AbiViewField<'__sacp_view>>::View,
                    #cbor_path::CborError,
                > {
                    <#wire_ty as #abi_path::AbiViewField<'__sacp_view>>::view_field(
                        self.#raw_ident()?,
                    )
                }
            }
        }
    });

    let known_ids = field_set.fields.iter().map(|field| field.id);
    let unknown_accessor = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
        quote! {
            #[inline]
            pub fn unknown_fields(
                &self,
            ) -> ::core::result::Result<
                impl ::core::iter::Iterator<
                    Item = ::core::result::Result<
                        #abi_path::UnknownFieldRef<'__sacp_view>,
                        #cbor_path::CborError,
                    >,
                > + '__sacp_view,
                #cbor_path::CborError,
            > {
                const __ABI_KNOWN_IDS: &[u32] = &[#(#known_ids),*];
                self.fields.unknown_fields(__ABI_KNOWN_IDS)
            }
        }
    } else {
        quote! {}
    };
    let extra_methods = extra_methods.unwrap_or_else(|| quote! {});

    quote! {
        #[derive(Debug, Clone, Copy)]
        #vis struct #view_name<'__sacp_view> {
            raw: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            fields: #abi_path::AbiFieldSetRef<'__sacp_view>,
            #(#storage_fields)*
        }

        impl<'__sacp_view> #view_name<'__sacp_view> {
            #[inline]
            pub fn from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_canonical(cbor)
            }

            #[inline]
            pub fn from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_value(value)
            }

            #[inline]
            pub fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }

            #(#accessors)*
            #unknown_accessor
            #extra_methods
        }

        impl<'__sacp_view> #abi_path::AbiView<'__sacp_view> for #view_name<'__sacp_view> {
            #[inline]
            fn view_from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                Self::view_from_value(cbor.root())
            }

            #[inline]
            fn view_from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                #(#storage_decls)*
                let __abi_fields = #abi_path::AbiFieldSetRef::scan(value, |__abi_entry| {
                    match __abi_entry.id {
                        #(#match_arms)*
                        #unknown_arm
                    }
                    ::core::result::Result::Ok(())
                })?;
                #(#required_checks)*
                ::core::result::Result::Ok(Self {
                    raw: value,
                    fields: __abi_fields,
                    #(#construct_fields)*
                })
            }

            #[inline]
            fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }
        }
    }
}

pub(crate) fn derive_enum_view(
    vis: &Visibility,
    name: &Ident,
    generics: &Generics,
    variants: &[VariantSpec<'_>],
    unknown_mode: UnknownVariantMode,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let view_name = format_ident!("{name}View");
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let view_lifetime: Lifetime = syn::parse_quote!('__sacp_view);
    let view_ty_generics = ty_generics_with_lifetime(generics, &view_lifetime);
    let known_ids = variants.iter().map(|variant| variant.id);
    let non_unit_variants = variants
        .iter()
        .filter(|variant| !variant.unit)
        .collect::<Vec<_>>();
    let payload_cache_name = format_ident!("{name}ViewPayload");

    let payload_views = variants
        .iter()
        .filter(|variant| !variant.unit)
        .map(|variant| {
            let payload_view_name = variant_payload_view_name(name, variant.ident);
            field_set_view_tokens(
                vis,
                &payload_view_name,
                &variant.fields,
                attrs.unknown_fields,
                attrs,
                None,
            )
        });
    let payload_cache_variants = non_unit_variants.iter().map(|variant| {
        let ident = variant.ident;
        let payload_view_name = variant_payload_view_name(name, variant.ident);
        quote! { #ident(#payload_view_name<'__sacp_view>), }
    });
    let payload_cache = if non_unit_variants.is_empty() {
        quote! {}
    } else {
        quote! {
            #[derive(Debug, Clone, Copy)]
            enum #payload_cache_name<'__sacp_view> {
                #(#payload_cache_variants)*
            }
        }
    };
    let payload_cache_field = if non_unit_variants.is_empty() {
        quote! {}
    } else {
        quote! {
            payload_view: ::core::option::Option<#payload_cache_name<'__sacp_view>>,
        }
    };
    let payload_cache_decl = if non_unit_variants.is_empty() {
        quote! {}
    } else {
        quote! {
            let mut __abi_payload_view: ::core::option::Option<
                #payload_cache_name<'__sacp_view>
            > = ::core::option::Option::None;
        }
    };
    let payload_cache_init = if non_unit_variants.is_empty() {
        quote! {}
    } else {
        quote! {
            payload_view: __abi_payload_view,
        }
    };

    let known_validation_arms = variants.iter().map(|variant| {
        let id = variant.id;
        if variant.unit {
            quote! {
                #id => {
                    <() as #abi_path::AbiViewField<'__sacp_view>>::view_field(__abi_payload)?;
                }
            }
        } else {
            let payload_view_name = variant_payload_view_name(name, variant.ident);
            let variant_ident = variant.ident;
            quote! {
                #id => {
                    let __abi_view = #payload_view_name::from_value(__abi_payload)?;
                    __abi_payload_view = ::core::option::Option::Some(
                        #payload_cache_name::#variant_ident(__abi_view),
                    );
                }
            }
        }
    });
    let unknown_validation_arm = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        quote! { _ => {} }
    } else {
        quote! {
            _ => {
                return Err(#cbor_path::CborError::new(
                    #cbor_path::ErrorCode::UnknownEnumVariant,
                    __abi_id_value.offset(),
                ));
            }
        }
    };

    let variant_methods = variants.iter().map(|variant| {
        let method_suffix = snake_ident(variant.ident);
        let is_method = format_ident!("is_{method_suffix}");
        let as_method = format_ident!("as_{method_suffix}");
        let id = variant.id;
        if variant.unit {
            quote! {
                #[inline]
                pub fn #is_method(&self) -> bool {
                    self.variant_id == #id
                }
            }
        } else {
            let payload_view_name = variant_payload_view_name(name, variant.ident);
            let variant_ident = variant.ident;
            quote! {
                #[inline]
                pub fn #is_method(&self) -> bool {
                    self.variant_id == #id
                }

                #[inline]
                pub fn #as_method(
                    &self,
                ) -> ::core::result::Result<
                    ::core::option::Option<#payload_view_name<'__sacp_view>>,
                    #cbor_path::CborError,
                > {
                    if self.variant_id == #id {
                        match self.payload_view {
                            ::core::option::Option::Some(
                                #payload_cache_name::#variant_ident(view)
                            ) => ::core::result::Result::Ok(::core::option::Option::Some(view)),
                            _ => ::core::result::Result::Err(#cbor_path::CborError::new(
                                #cbor_path::ErrorCode::InvalidAbiValue,
                                self.payload.offset(),
                            )),
                        }
                    } else {
                        ::core::result::Result::Ok(::core::option::Option::None)
                    }
                }
            }
        }
    });
    let unknown_method = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        quote! {
            #[inline]
            pub fn unknown_variant(
                &self,
            ) -> ::core::option::Option<#abi_path::UnknownVariantRef<'__sacp_view>> {
                const __ABI_KNOWN_IDS: &[u32] = &[#(#known_ids),*];
                if __ABI_KNOWN_IDS.binary_search(&self.variant_id).is_err() {
                    ::core::option::Option::Some(#abi_path::UnknownVariantRef {
                        id: self.variant_id,
                        payload: self.payload,
                    })
                } else {
                    ::core::option::Option::None
                }
            }
        }
    } else {
        quote! {
            #[inline]
            pub fn unknown_variant(
                &self,
            ) -> ::core::option::Option<#abi_path::UnknownVariantRef<'__sacp_view>> {
                ::core::option::Option::None
            }
        }
    };

    Ok(quote! {
        #(#payload_views)*
        #payload_cache

        #[derive(Debug, Clone, Copy)]
        #vis struct #view_name<'__sacp_view> {
            raw: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            variant_id: u32,
            payload: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            #payload_cache_field
        }

        impl<'__sacp_view> #view_name<'__sacp_view> {
            #[inline]
            pub fn from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_canonical(cbor)
            }

            #[inline]
            pub fn from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                <Self as #abi_path::AbiView<'__sacp_view>>::view_from_value(value)
            }

            #[inline]
            pub fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }

            #[inline]
            pub fn variant_id(&self) -> u32 {
                self.variant_id
            }

            #[inline]
            pub fn payload_raw(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.payload
            }

            #(#variant_methods)*
            #unknown_method
        }

        impl<'__sacp_view> #abi_path::AbiView<'__sacp_view> for #view_name<'__sacp_view> {
            #[inline]
            fn view_from_canonical(
                cbor: #abi_path::__private::sacp_cbor::CanonicalCborRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                Self::view_from_value(cbor.root())
            }

            #[inline]
            fn view_from_value(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                let __abi_array = value.array()?;
                if __abi_array.len() != 2 {
                    return Err(#cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        value.offset(),
                    ));
                }
                let mut __abi_iter = __abi_array.iter();
                let __abi_id_value = __abi_iter
                    .next()
                    .ok_or_else(|| #cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        value.offset(),
                    ))??;
                let __abi_id = #abi_path::__private::decode_abi_id(__abi_id_value)?;
                let __abi_payload = __abi_iter
                    .next()
                    .ok_or_else(|| #cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        value.offset(),
                    ))??;
                #payload_cache_decl
                match __abi_id {
                    #(#known_validation_arms)*
                    #unknown_validation_arm
                }
                ::core::result::Result::Ok(Self {
                    raw: value,
                    variant_id: __abi_id,
                    payload: __abi_payload,
                    #payload_cache_init
                })
            }

            #[inline]
            fn raw_value(
                &self,
            ) -> #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view> {
                self.raw
            }
        }

        impl<'__sacp_view> #abi_path::AbiViewField<'__sacp_view>
            for #name #view_ty_generics
        {
            type View = #view_name<'__sacp_view>;

            #[inline]
            fn view_field(
                value: #abi_path::__private::sacp_cbor::query::CborValueRef<'__sacp_view>,
            ) -> ::core::result::Result<Self::View, #cbor_path::CborError> {
                <#view_name<'__sacp_view> as #abi_path::AbiView<'__sacp_view>>::view_from_value(
                    value,
                )
            }
        }
    })
}

fn variant_payload_view_name(enum_name: &Ident, variant_name: &Ident) -> Ident {
    format_ident!("{enum_name}{variant_name}View")
}

fn snake_ident(ident: &Ident) -> String {
    let name = ident.to_string();
    let mut out = String::new();
    for (idx, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
