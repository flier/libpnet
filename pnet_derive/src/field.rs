use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use syn;

use types::{parse_primitive, parse_vec, Endianness, Result};

pub struct Field {
    ident: syn::Ident,
    ty: syn::Type,
    is_payload: bool,
    packet_length: Option<TokenStream>,
    construct_with: Option<Vec<syn::Ident>>,
}

impl Field {
    pub fn parse(field: syn::Field) -> Result<Self> {
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
                            if parse_primitive(&ident.to_string()).is_none() {
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

        let field = Field {
            ident: field.ident.unwrap(),
            ty: field.ty,
            is_payload,
            packet_length,
            construct_with: if construct_with.is_empty() {
                None
            } else {
                Some(construct_with)
            },
        };

        if let Some((inner_ty, item_size, _)) = field.as_vec() {
            if !field.is_payload && field.packet_length.is_none() {
                bail!("variable length field must have #[length_fn] attribute")
            }

            if inner_ty == "Vec" {
                bail!("variable length fields may not contain vectors")
            } else if inner_ty != "u8" || item_size % 8 != 0 {
                bail!("unimplemented variable length field")
            }
        } else if field.as_primitive().is_none() && field.construct_with.is_none() {
            bail!("non-primitive field types must specify #[construct_with]")
        }

        Ok(field)
    }

    pub fn field_name(&self) -> &syn::Ident {
        &self.ident
    }

    pub fn is_payload(&self) -> bool {
        self.is_payload
    }

    pub fn as_primitive(&self) -> Option<(usize, Option<Endianness>)> {
        match self.ty {
            syn::Type::Path(syn::TypePath {
                path: syn::Path { ref segments, .. },
                ..
            }) if segments.len() == 1 =>
            {
                parse_primitive(&segments.last()?.value().ident.to_string())
            }
            _ => None,
        }
    }

    pub fn as_vec(&self) -> Option<(syn::Ident, usize, Option<Endianness>)> {
        parse_vec(&self.ty)
    }

    pub fn generate_accessor(&self, mutable: bool, bits_offset: &mut usize) -> TokenStream {
        if let Some((bits_size, endianess)) = self.as_primitive() {
            self.generate_primitive_accessor(bits_offset, bits_size, endianess)
        } else if let Some((inner_ty, item_size, endianess)) = self.as_vec() {
            self.generate_vec_accessor(mutable, bits_offset, &inner_ty, item_size, endianess)
        } else {
            self.generate_typed_accessor(bits_offset)
        }
    }

    fn generate_primitive_accessor(
        &self,
        bits_offset: &mut usize,
        bits_size: usize,
        endianess: Option<Endianness>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!(
                        "Get the {} field.
This field is always stored in {} endianess within the struct, but this accessor returns host order.",
                        field_name, endianess.map_or("host", |e| e.name())
                    );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let read_ops = read_operations(*bits_offset, bits_size, endianess, quote!{ self.packet });

        *bits_offset += bits_size;

        quote! {
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
        endianess: Option<Endianness>,
    ) -> TokenStream {
        let current_offset = (*bits_offset + 7) / 8;

        let raw_accessors = if !self.is_payload {
            Some(self.generate_vec_raw_accessors(mutable, current_offset))
        } else {
            None
        };

        if let Some((bits_size, endianess)) = parse_primitive(&inner_ty.to_string()) {
            self.generate_vec_primitive_accessor(current_offset, &inner_ty, bits_size, endianess)
        } else {
            quote!{}
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

            quote! {
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

            Some(quote! {
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

        quote! {
            #get_field_raw

            #get_field_raw_mut
        }
    }

    fn generate_vec_primitive_accessor(
        &self,
        current_offset: usize,
        inner_ty: &syn::Ident,
        bits_size: usize,
        endianess: Option<Endianness>,
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
            let read_ops = read_operations(0, bits_size, endianess, quote! { chunk });

            quote! {
                packet.chunks(#item_size).map(|chunk| { #read_ops }).collect()
            }
        };

        quote! {
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

    fn generate_typed_accessor(&self, bits_offset: &mut usize) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());

        let ctor = if let Some(ref arg_types) = self.construct_with {
            let mut args = vec![];

            for arg_ty in arg_types {
                let (bits_size, endianess) = parse_primitive(&arg_ty.to_string())
                    .expect("arguments to #[construct_with] must be primitives");

                let read_ops =
                    read_operations(*bits_offset, bits_size, endianess, quote! { self.packet });

                args.push(quote! {
                    #(#read_ops)*
                });

                *bits_offset += bits_size;
            }

            quote! {
                #field_ty ::new( #(#args),* )
            }
        } else {
            let bytes_offset = (*bits_offset + 7) / 8;

            quote! {
                #field_ty ::new(&self.packet[#bytes_offset ..])
            }
        };

        let comment = format!("Get the value of the {} field", field_name);

        quote! {
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
        if let Some((bits_size, endianess)) = self.as_primitive() {
            self.generate_primitive_mutator(bits_offset, bits_size, endianess)
        } else if let Some((inner_ty, item_size, endianess)) = self.as_vec() {
            if let Some((bits_size, endianess)) = parse_primitive(&inner_ty.to_string()) {
                self.generate_vec_primitive_mutator(bits_offset, &inner_ty, bits_size, endianess)
            } else {
                quote!{}
            }
        } else {
            self.generate_typed_mutator(bits_offset)
        }
    }

    fn generate_primitive_mutator(
        &self,
        bits_offset: &mut usize,
        bits_size: usize,
        endianess: Option<Endianness>,
    ) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let endianess_name = endianess.map_or("host", |e| e.name());
        let comment = format!(
                            "Set the {} field.
    This field is always stored in {} endianess within the struct, but this accessor returns host order.",
                            field_name, endianess_name
                        );
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
        let write_ops = write_operations(
            *bits_offset,
            bits_size,
            endianess,
            quote! { self.packet },
            quote! { val },
        );

        *bits_offset += bits_size;

        quote! {
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
        endianess: Option<Endianness>,
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
            let write_ops = write_operations(0, bits_size, endianess, quote! { buf }, quote! { v });

            quote!{
                let buf = vals.iter().flat_map(|&v| {
                    let mut buf = vec![0u8; #bytes_size];

                    #write_ops

                    buf.into_iter()
                }).collect::<Vec<_>>();

                packet.copy_from_slice(buf.as_slice())
            }
        };

        quote! {
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

    fn generate_typed_mutator(&self, bits_offset: &mut usize) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Set the value of the {} field", field_name);
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

        let setter = if let Some(ref arg_types) = self.construct_with {
            let mut set_args = vec![];

            for (idx, arg_ty) in arg_types.iter().enumerate() {
                let (bits_size, endianess) = parse_primitive(&arg_ty.to_string())
                    .expect("arguments to #[construct_with] must be primitives");

                let write_ops = write_operations(
                    *bits_offset,
                    bits_size,
                    endianess,
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
        } else {
            let bytes_offset = (*bits_offset + 7) / 8;

            quote! {
                self.packet[#bytes_offset .. #bytes_offset + ::std::mem::size_of_val(vals)].copy_from_slice(&vals[..]);
            }
        };

        quote! {
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
    bits_size: usize,
    endianess: Option<Endianness>,
    packet: T,
) -> TokenStream {
    if bits_offset % 8 == 0 && bits_size % 8 == 0 && bits_size <= 64 {
        let bytes_offset = bits_offset / 8;
        let endianess_name = syn::Ident::new(
            match endianess {
                Some(Endianness::Little) => "LittenEndia",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits_size {
            8 => quote! {
                #packet[#bytes_offset]
            },
            16 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u16(&#packet[#bytes_offset..])
            },
            24 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u24(&#packet[#bytes_offset..])
            },
            32 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u32(&#packet[#bytes_offset..])
            },
            48 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u48(&#packet[#bytes_offset..])
            },
            64 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u64(&#packet[#bytes_offset..])
            },
            _ => quote!{
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_uint(&#packet[#bytes_offset..], #bits_size / 8)
            },
        }
    } else {
        quote!{}
    }
}

fn write_operations<T: ToTokens, V: ToTokens>(
    bits_offset: usize,
    bits_size: usize,
    endianess: Option<Endianness>,
    packet: T,
    val: V,
) -> TokenStream {
    if bits_offset % 8 == 0 && bits_size % 8 == 0 && bits_size <= 64 {
        let bytes_offset = bits_offset / 8;
        let endianess_name = syn::Ident::new(
            match endianess {
                Some(Endianness::Little) => "LittenEndian",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits_size {
            8 => quote! {
                #packet[#bytes_offset] = #val;
            },
            16 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u16(&mut #packet[#bytes_offset..], #val);
            },
            24 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u24(&mut #packet[#bytes_offset..], #val);
            },
            32 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u32(&mut #packet[#bytes_offset..], #val);
            },
            48 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u48(&mut #packet[#bytes_offset..], #val);
            },
            64 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u64(&mut #packet[#bytes_offset..], #val);
            },
            _ => quote!{
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_uint(&mut #packet[#bytes_offset..], #bits_size / 8, #val);
            },
        }
    } else {
        quote!{}
    }
}
