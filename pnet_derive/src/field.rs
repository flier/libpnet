use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use syn::{self, spanned::Spanned};

use types::{parse_primitive, Endianness, Result};

#[derive(Clone, Debug)]
pub struct Field {
    ident: syn::Ident,
    ty: syn::Type,
    span: Span,
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Kind {
    Primitive {
        bits: usize,
        endianness: Option<Endianness>,
    },
    Vec {
        item_ty: syn::Ident,
        item_bits: usize,
        endianness: Option<Endianness>,
        is_payload: bool,
        packet_length: Option<TokenStream>,
    },
    Custom {
        construct_with: Vec<syn::Ident>,
    },
}

impl Field {
    pub fn parse(field: syn::Field) -> Result<Self> {
        let field_span = field.span();
        let field_name = field
            .ident
            .ok_or_else(|| format_err!("all fields in a packet must be named"))?;
        let field_ty = field.ty;

        let mut is_payload = false;
        let mut packet_length = None;
        let mut construct_with = vec![];

        for attr in field.attrs {
            match attr.interpret_meta() {
                Some(syn::Meta::Word(ref ident)) if ident == "payload" => {
                    is_payload = true;
                }
                Some(syn::Meta::List(syn::MetaList {
                    ref ident,
                    ref nested,
                    ..
                })) if ident == "construct_with" =>
                {
                    if nested.is_empty() {
                        bail!("#[construct_with] must have at least one argument")
                    }

                    for meta in nested {
                        if let syn::NestedMeta::Meta(syn::Meta::Word(ident)) = meta {
                            if parse_primitive(&ident).is_none() {
                                bail!("arguments to #[construct_with] must be primitives")
                            }

                            construct_with.push(ident.clone())
                        } else {
                            bail!("#[construct_with] should be of the form #[construct_with(<types>)]")
                        }
                    }
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length" =>
                {
                    let n = match lit {
                        syn::Lit::Str(lit) => lit.value().parse()?,
                        syn::Lit::Int(lit) => lit.value(),
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    };

                    packet_length = Some(quote!{ #n });
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length_fn" =>
                {
                    let length_fn = match lit {
                        syn::Lit::Str(lit) => syn::Ident::new(&lit.value(), Span::call_site()),
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    };

                    packet_length = Some(quote! {
                        #length_fn(&self.to_immutable())
                    });
                }
                _ => bail!("unknown attribute {}", attr.into_token_stream()),
            }
        }

        match field_ty {
            syn::Type::Path(syn::TypePath {
                path: syn::Path { ref segments, .. },
                ..
            }) if segments.len() == 1 =>
            {
                let segment = segments.last().unwrap();
                let ty = segment.value();

                if ty.ident == "Vec" {
                    match ty.arguments {
                        syn::PathArguments::AngleBracketed(
                            syn::AngleBracketedGenericArguments { ref args, .. },
                        ) if args.len() == 1 =>
                        {
                            match args.last().unwrap().value() {
                                syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
                                    path: syn::Path { segments, .. },
                                    ..
                                })) if segments.len() == 1 =>
                                {
                                    let segment = segments.last().unwrap();
                                    let item_ty = &segment.value().ident;

                                    if let Some((item_bits, endianness)) = parse_primitive(item_ty)
                                    {
                                        if !is_payload && packet_length.is_none() {
                                            bail!("variable length field must have #[length] or #[length_fn] attribute")
                                        }
                                        if item_ty == "Vec" {
                                            bail!("variable length fields may not contain vectors")
                                        }
                                        if item_bits % 8 != 0 {
                                            bail!("variable length fields must align to byte")
                                        }

                                        Some(Kind::Vec {
                                            item_ty: item_ty.clone(),
                                            item_bits,
                                            endianness,
                                            is_payload,
                                            packet_length,
                                        })
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    }
                } else if let Some((bits, endianness)) = parse_primitive(&ty.ident) {
                    Some(Kind::Primitive { bits, endianness })
                } else {
                    None
                }
            }
            _ => None,
        }.or_else(|| {
            if !construct_with.is_empty() {
                Some(Kind::Custom { construct_with })
            } else {
                None
            }
        })
            .ok_or_else(|| format_err!("non-primitive field types must specify #[construct_with]"))
            .map(|kind| Field {
                ident: field_name,
                ty: field_ty,
                span: field_span,
                kind,
            })
    }

    pub fn name(&self) -> &syn::Ident {
        &self.ident
    }

    pub fn ty(&self) -> &syn::Type {
        &self.ty
    }

    pub fn as_primitive(&self) -> Option<(usize, Option<Endianness>)> {
        match self.kind {
            Kind::Primitive { bits, endianness } => Some((bits, endianness)),
            _ => None,
        }
    }

    pub fn as_vec(
        &self,
    ) -> Option<(
        &syn::Ident,
        usize,
        Option<Endianness>,
        bool,
        Option<&TokenStream>,
    )> {
        match self.kind {
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                is_payload,
                ref packet_length,
            } => Some((
                item_ty,
                item_bits,
                endianness,
                is_payload,
                packet_length.as_ref(),
            )),
            _ => None,
        }
    }

    pub fn as_custom(&self) -> Option<&[syn::Ident]> {
        match self.kind {
            Kind::Custom { ref construct_with } => Some(construct_with),
            _ => None,
        }
    }

    pub fn is_payload(&self) -> bool {
        match self.kind {
            Kind::Vec { is_payload, .. } => is_payload,
            _ => false,
        }
    }

    pub fn generate_accessor(&self, mutable: bool, bits_offset: &mut usize) -> TokenStream {
        match self.kind {
            Kind::Primitive { bits, endianness } => {
                self.generate_primitive_accessor(bits_offset, bits, endianness)
            }
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                is_payload,
                ref packet_length,
            } => self.generate_vec_accessor(
                mutable,
                bits_offset,
                item_ty,
                item_bits,
                endianness,
                is_payload,
                packet_length,
            ),
            Kind::Custom { ref construct_with } => {
                self.generate_custom_accessor(bits_offset, construct_with)
            }
        }
    }

    fn generate_primitive_accessor(
        &self,
        bits_offset: &mut usize,
        bits_size: usize,
        endianness: Option<Endianness>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Get the {} field.
This field is always stored in {} endianness within the struct, but this accessor returns host order.",
            field_name, endianness.map_or("host", |e| e.name())
        );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let read_ops = read_operations(*bits_offset, bits_size, endianness, quote!{ self.packet });

        *bits_offset += bits_size;

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> #field_ty {
                #(#read_ops)*
            }
        }
    }

    fn generate_vec_accessor(
        &self,
        mutable: bool,
        bits_offset: &mut usize,
        inner_ty: &syn::Ident,
        item_size: usize,
        endianness: Option<Endianness>,
        is_payload: bool,
        packet_length: &Option<TokenStream>,
    ) -> TokenStream {
        let current_offset = (*bits_offset + 7) / 8;

        let raw_accessors = if !is_payload {
            Some(self.generate_vec_raw_accessors(mutable, current_offset))
        } else {
            None
        };

        if let Some((bits_size, endianness)) = parse_primitive(&inner_ty) {
            let vec_primitive_accessor = self.generate_vec_primitive_accessor(
                current_offset,
                &inner_ty,
                bits_size,
                endianness,
            );

            quote_spanned! { self.span =>
                #raw_accessors

                #vec_primitive_accessor
            }
        } else {
            quote_spanned! { self.span =>
                #raw_accessors
            }
        }
    }

    fn generate_vec_raw_accessors(&self, mutable: bool, current_offset: usize) -> TokenStream {
        let field_name = &self.ident;

        let get_field_raw = {
            let comment = format!(
                "Get the raw &[u8] value of the {} field, without copying",
                field_name
            );
            let get_field_raw =
                syn::Ident::new(&format!("get_{}_raw", field_name), Span::call_site());

            quote_spanned! { self.span =>
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #get_field_raw(&self) -> &[u8] {
                    &self.packet[#current_offset..]
                }
            }
        };

        let get_field_raw_mut = if mutable {
            let comment = format!(
                "Get the raw &mut [u8] value of the {} field, without copying",
                field_name
            );
            let get_field_raw_mut =
                syn::Ident::new(&format!("get_{}_raw_mut", field_name), Span::call_site());

            Some(quote_spanned! { self.span =>
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #get_field_raw_mut(&mut self) -> &mut [u8] {
                    &mut self.packet[#current_offset..]
                }
            })
        } else {
            None
        };

        quote_spanned! { self.span =>
            #get_field_raw

            #get_field_raw_mut
        }
    }

    fn generate_vec_primitive_accessor(
        &self,
        current_offset: usize,
        inner_ty: &syn::Ident,
        bits_size: usize,
        endianness: Option<Endianness>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let comment = format!(
            "Get the value of the {} field (copies contents)",
            field_name
        );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let read_ops = if inner_ty == "u8" {
            quote! {
                packet.to_vec()
            }
        } else {
            let item_size = bits_size / 8;
            let read_ops = read_operations(0, bits_size, endianness, quote! { chunk });

            quote! {
                packet.chunks(#item_size).map(|chunk| { #read_ops }).collect()
            }
        };

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> Vec<#inner_ty> {
                let packet = &self.packet[#current_offset..];

                #read_ops
            }
        }
    }

    fn generate_custom_accessor(
        &self,
        bits_offset: &mut usize,
        arg_types: &[syn::Ident],
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());

        let ctor = if arg_types.is_empty() {
            let bytes_offset = (*bits_offset + 7) / 8;

            quote! {
                #field_ty ::new(&self.packet[#bytes_offset ..])
            }
        } else {
            let mut args = vec![];

            for arg_ty in arg_types {
                let (bits_size, endianness) = parse_primitive(&arg_ty)
                    .expect("arguments to #[construct_with] must be primitives");

                let read_ops =
                    read_operations(*bits_offset, bits_size, endianness, quote! { self.packet });

                args.push(quote! {
                    #(#read_ops)*
                });

                *bits_offset += bits_size;
            }

            quote! {
                #field_ty ::new( #(#args),* )
            }
        };

        let comment = format!("Get the value of the {} field", field_name);

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> #field_ty {
                #ctor
            }
        }
    }

    pub fn generate_mutator(&self, bits_offset: &mut usize) -> TokenStream {
        match self.kind {
            Kind::Primitive { bits, endianness } => {
                self.generate_primitive_mutator(bits_offset, bits, endianness)
            }
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                is_payload,
                ref packet_length,
            } => self.generate_vec_primitive_mutator(
                bits_offset,
                item_ty,
                item_bits,
                endianness,
                is_payload,
                packet_length,
            ),
            Kind::Custom { ref construct_with } => {
                self.generate_custom_mutator(bits_offset, construct_with)
            }
        }
    }

    fn generate_primitive_mutator(
        &self,
        bits_offset: &mut usize,
        bits_size: usize,
        endianness: Option<Endianness>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let endianness_name = endianness.map_or("host", |e| e.name());
        let comment = format!("Set the {} field.
This field is always stored in {} endianness within the struct, but this accessor returns host order.",
                            field_name, endianness_name
                        );
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
        let write_ops = write_operations(
            *bits_offset,
            bits_size,
            endianness,
            quote! { self.packet },
            quote! { val },
        );

        *bits_offset += bits_size;

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, val: #field_ty) {
                #(#write_ops)*
            }
        }
    }

    fn generate_vec_primitive_mutator(
        &self,
        bits_offset: &mut usize,
        inner_ty: &syn::Ident,
        bits_size: usize,
        endianness: Option<Endianness>,
        is_payload: bool,
        packet_length: &Option<TokenStream>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let comment = format!(
            "Set the value of the {} field (copies contents)",
            field_name
        );
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
        let current_offset = (*bits_offset + 7) / 8;
        let write_ops = if inner_ty == "u8" {
            quote! {
                packet.copy_from_slice(vals)
            }
        } else {
            let bytes_size = (bits_size + 7) / 8;
            let write_ops =
                write_operations(0, bits_size, endianness, quote! { buf }, quote! { v });

            quote!{
                let buf = vals.iter().flat_map(|&v| {
                    let mut buf = vec![0u8; #bytes_size];

                    #write_ops

                    buf.into_iter()
                }).collect::<Vec<_>>();

                packet.copy_from_slice(buf.as_slice())
            }
        };

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, vals: &[#inner_ty]) {
                let packet = &mut self.packet[#current_offset..];

                #write_ops
            }
        }
    }

    fn generate_custom_mutator(
        &self,
        bits_offset: &mut usize,
        arg_types: &[syn::Ident],
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Set the value of the {} field", field_name);
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

        let setter = if arg_types.is_empty() {
            let bytes_offset = (*bits_offset + 7) / 8;

            quote! {
                self.packet[#bytes_offset .. #bytes_offset + ::std::mem::size_of_val(vals)].copy_from_slice(&vals[..]);
            }
        } else {
            let mut set_args = vec![];

            for (idx, arg_ty) in arg_types.iter().enumerate() {
                let (bits_size, endianness) = parse_primitive(&arg_ty)
                    .expect("arguments to #[construct_with] must be primitives");

                let write_ops = write_operations(
                    *bits_offset,
                    bits_size,
                    endianness,
                    quote! { self.packet },
                    quote!{ vals.#idx },
                );

                set_args.push(quote! {
                    #(#write_ops)*
                });

                *bits_offset += bits_size;
            }

            quote! {
                #(#set_args)*
            }
        };

        quote_spanned! { self.span =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, val: #field_ty) {
                use pnet_macros_support::packet::PrimitiveValues;

                let vals = val.to_primitive_values();

                #setter
            }
        }
    }
}

fn read_operations<T: ToTokens>(
    bits_offset: usize,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
) -> TokenStream {
    if bits_offset % 8 == 0 && bits % 8 == 0 && bits <= 64 {
        let bytes_offset = bits_offset / 8;
        let endianness_name = syn::Ident::new(
            match endianness {
                Some(Endianness::Little) => "LittenEndia",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits {
            8 => quote! {
                #packet[#bytes_offset]
            },
            16 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u16(&#packet[#bytes_offset..])
            },
            24 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u24(&#packet[#bytes_offset..])
            },
            32 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u32(&#packet[#bytes_offset..])
            },
            48 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u48(&#packet[#bytes_offset..])
            },
            64 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u64(&#packet[#bytes_offset..])
            },
            _ => {
                let bytes = bits / 8;

                quote!{
                    <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_uint(&#packet[#bytes_offset..], #bytes)
                }
            }
        }
    } else {
        unimplemented!()
    }
}

fn write_operations<T: ToTokens, V: ToTokens>(
    bits_offset: usize,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
    val: V,
) -> TokenStream {
    if bits_offset % 8 == 0 && bits % 8 == 0 && bits <= 64 {
        let bytes_offset = bits_offset / 8;
        let endianness_name = syn::Ident::new(
            match endianness {
                Some(Endianness::Little) => "LittenEndian",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits {
            8 => quote! {
                #packet[#bytes_offset] = #val;
            },
            16 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u16(&mut #packet[#bytes_offset..], #val);
            },
            24 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u24(&mut #packet[#bytes_offset..], #val);
            },
            32 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u32(&mut #packet[#bytes_offset..], #val);
            },
            48 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u48(&mut #packet[#bytes_offset..], #val);
            },
            64 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u64(&mut #packet[#bytes_offset..], #val);
            },
            _ => {
                let bytes = bits / 8;

                quote!{
                    <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_uint(&mut #packet[#bytes_offset..], #bytes, #val);
                }
            }
        }
    } else {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ident {
        ($name:expr) => {
            ident!($name, ::proc_macro2::Span::call_site())
        };
        ($name:expr, $span:expr) => {
            ::syn::Ident::new($name, $span)
        };
    }

    #[test]
    fn test_read_operations() {
        let read_ops = [
            (0, 8, Some(Endianness::Little), quote! { packet[0usize] }),
            (8, 16, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&packet[1usize..]) }),
            (16, 24, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::read_u24(&packet[2usize..]) }),
            (24, 32, Some(Endianness::Little), quote! { <::byteorder::LittenEndia as ::byteorder::ByteOrder>::read_u32(&packet[3usize..]) }),
            (32, 48, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u48(&packet[4usize..]) }),
            (40, 64, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::read_u64(&packet[5usize..]) }),
            (48, 40, Some(Endianness::Little), quote! { <::byteorder::LittenEndia as ::byteorder::ByteOrder>::read_uint(&packet[6usize..], 5usize) }),
        ];

        for &(bits_offset, bits, endianness, ref code) in &read_ops {
            assert_eq!(
                read_operations(bits_offset, bits, endianness, quote! { packet }).to_string(),
                code.to_string()
            );
        }
    }

    #[test]
    fn test_write_operations() {
        let write_ops = [
            (0, 8, Some(Endianness::Little), quote! { packet[0usize] = val; }),
            (8, 16, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut packet[1usize..], val); }),
            (16, 24, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::write_u24(&mut packet[2usize..], val); }),
            (24, 32, Some(Endianness::Little), quote! { <::byteorder::LittenEndian as ::byteorder::ByteOrder>::write_u32(&mut packet[3usize..], val); }),
            (32, 48, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u48(&mut packet[4usize..], val); }),
            (40, 64, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::write_u64(&mut packet[5usize..], val); }),
            (48, 40, Some(Endianness::Little), quote! { <::byteorder::LittenEndian as ::byteorder::ByteOrder>::write_uint(&mut packet[6usize..], 5usize, val); }),
        ];

        for &(bits_offset, bits, endianness, ref code) in &write_ops {
            assert_eq!(
                write_operations(
                    bits_offset,
                    bits,
                    endianness,
                    quote! { packet },
                    quote! { val }
                ).to_string(),
                code.to_string()
            );
        }
    }

    #[test]
    fn test_primitive_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                foo: u8,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "foo");
        assert_eq!(field.as_primitive(), Some((8, Some(Endianness::Big))));

        let mut bits_offset = 0;

        assert_eq!(
            field.generate_accessor(false, &mut bits_offset).to_string(),
            quote! {
                #[doc = "Get the foo field.\nThis field is always stored in big endianness within the struct, but this accessor returns host order."]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_foo(&self) -> u8 {
                    self.packet[0usize]
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 8);

        assert_eq!(
            field.generate_mutator(&mut bits_offset).to_string(),
            quote!{
                #[doc = "Set the foo field.\nThis field is always stored in big endianness within the struct, but this accessor returns host order."]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn set_foo(&mut self, val: u8 ) {
                    self.packet[1usize] = val;
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 16);
    }

    #[test]
    fn test_field_with_unknown_attributes() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[foo]
                body: Vec<u16>,
            }
        };

        assert_eq!(
            Field::parse(fields.named.into_iter().next().unwrap())
                .unwrap_err()
                .to_string(),
            "unknown attribute # [ foo ]"
        );
    }

    #[test]
    fn test_vec_field_without_length() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                foo: Vec<u8>,
            }
        };

        assert_eq!(
            Field::parse(fields.named.into_iter().next().unwrap())
                .unwrap_err()
                .to_string(),
            "variable length field must have #[length] or #[length_fn] attribute"
        );
    }

    #[test]
    fn test_vec_field_with_vec_item() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                foo: Vec<Vec<u8>>,
            }
        };

        assert_eq!(
            Field::parse(fields.named.into_iter().next().unwrap())
                .unwrap_err()
                .to_string(),
            "non-primitive field types must specify #[construct_with]"
        );
    }

    #[test]
    fn test_vec_field_with_short_item() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[payload]
                foo: Vec<u4>,
            }
        };

        assert_eq!(
            Field::parse(fields.named.into_iter().next().unwrap())
                .unwrap_err()
                .to_string(),
            "variable length fields must align to byte"
        );
    }

    #[test]
    fn test_custom_field_without_construct_with() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                body: HashSet<u16>,
            }
        };

        assert_eq!(
            Field::parse(fields.named.into_iter().next().unwrap())
                .unwrap_err()
                .to_string(),
            "non-primitive field types must specify #[construct_with]"
        );
    }

    #[test]
    fn test_payload_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[payload]
                body: Vec<u8>,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "body");
        assert_eq!(
            field.as_vec().map(
                |(item_ty, item_bits, endianness, is_payload, packet_length)| (
                    item_ty.clone(),
                    item_bits,
                    endianness,
                    is_payload,
                    packet_length.map(|s| s.to_string())
                )
            ),
            Some((ident!("u8"), 8, Some(Endianness::Big), true, None))
        );

        let mut bits_offset = 16;

        assert_eq!(
            field.generate_accessor(false, &mut bits_offset).to_string(),
            quote! {
                #[doc = "Get the value of the body field (copies contents)" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn get_body(&self) -> Vec <u8> {
                    let packet = &self.packet[2usize..];
                    packet.to_vec()
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 16);

        assert_eq!(
            field.generate_mutator(&mut bits_offset).to_string(),
            quote! {
               #[doc = "Set the value of the body field (copies contents)"]
               #[inline]
               #[allow(trivial_numeric_casts)]
               #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
               pub fn set_body(&mut self, vals: &[u8]) {
                   let packet = &mut self.packet[2usize..];
                   packet.copy_from_slice(vals)
               }
            }.to_string()
        );
        assert_eq!(bits_offset, 16);
    }

    #[test]
    fn test_payload_field_with_u16() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[payload]
                body: Vec<u16>,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "body");
        assert_eq!(
            field.as_vec().map(
                |(item_ty, item_bits, endianness, is_payload, packet_length)| (
                    item_ty.clone(),
                    item_bits,
                    endianness,
                    is_payload,
                    packet_length.map(|s| s.to_string())
                )
            ),
            Some((ident!("u16"), 16, Some(Endianness::Big), true, None))
        );

        let mut bits_offset = 16;

        assert_eq!(
            field.generate_accessor(false, &mut bits_offset).to_string(),
            quote! {
                #[doc = "Get the value of the body field (copies contents)" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn get_body(&self) -> Vec <u16> {
                    let packet = &self.packet[2usize..];
                    packet.chunks(2usize).map(|chunk| {
                        <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&chunk[0usize..])
                    }).collect()
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 16);

        assert_eq!(
            field.generate_mutator(&mut bits_offset).to_string(),
            quote! {
               #[doc = "Set the value of the body field (copies contents)"]
               #[inline]
               #[allow(trivial_numeric_casts)]
               #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
               pub fn set_body(&mut self, vals: &[u16]) {
                   let packet = &mut self.packet[2usize..];
                   let buf = vals.iter().flat_map(|&v| {
                       let mut buf = vec![0u8; 2usize];
                       <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut buf[0usize..], v);
                       buf.into_iter()
                    }).collect::<Vec<_>>();

                    packet.copy_from_slice(buf.as_slice())
               }
            }.to_string()
        );
        assert_eq!(bits_offset, 16);
    }

    #[test]
    fn test_custom_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[construct_with(u16)]
                pub hardware_type: ArpHardwareType,

                #[construct_with(u8, u8, u8, u8, u8, u8)]
                pub sender_hw_addr: MacAddr,
            }
        };

        let mut iter = fields.named.into_iter();
        let hardware_type = Field::parse(iter.next().unwrap()).unwrap();

        assert_eq!(hardware_type.name(), "hardware_type");
        assert_eq!(hardware_type.as_custom(), Some(&[ident!("u16")][..]));

        let mut bits_offset = 16;

        assert_eq!(
            hardware_type
                .generate_accessor(false, &mut bits_offset)
                .to_string(),
            quote!{
                #[doc="Get the value of the hardware_type field" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_hardware_type(&self) -> ArpHardwareType {
                    ArpHardwareType::new(
                        <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&self.packet[2usize..])
                    )
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 32);

        assert_eq!(
            hardware_type.generate_mutator(&mut bits_offset).to_string(),
            quote!{
                #[doc="Set the value of the hardware_type field"]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn set_hardware_type(&mut self, val: ArpHardwareType) {
                    use pnet_macros_support::packet::PrimitiveValues;
                    let vals = val.to_primitive_values();

                    <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut self.packet[4usize..], vals.0usize);
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 48);

        let sender_hw_addr = Field::parse(iter.next().unwrap()).unwrap();

        assert_eq!(sender_hw_addr.name(), "sender_hw_addr");
        assert_eq!(
            sender_hw_addr.as_custom(),
            Some(
                &[
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8")
                ][..]
            )
        );

        assert_eq!(
            sender_hw_addr
                .generate_accessor(false, &mut bits_offset)
                .to_string(),
            quote!{
                #[doc="Get the value of the sender_hw_addr field" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_sender_hw_addr(&self) -> MacAddr {
                    MacAddr::new(
                        self.packet[6usize],
                        self.packet[7usize],
                        self.packet[8usize],
                        self.packet[9usize],
                        self.packet[10usize],
                        self.packet[11usize]
                    )
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 96);

        assert_eq!(
            sender_hw_addr
                .generate_mutator(&mut bits_offset)
                .to_string(),
            quote!{
                #[doc="Set the value of the sender_hw_addr field"]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn set_sender_hw_addr(&mut self, val: MacAddr) {
                    use pnet_macros_support::packet::PrimitiveValues;
                    let vals = val.to_primitive_values();

                    self.packet[12usize] = vals.0usize;
                    self.packet[13usize] = vals.1usize;
                    self.packet[14usize] = vals.2usize;
                    self.packet[15usize] = vals.3usize;
                    self.packet[16usize] = vals.4usize;
                    self.packet[17usize] = vals.5usize;
                }
            }.to_string()
        );
        assert_eq!(bits_offset, 144);
    }
}
