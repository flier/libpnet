#![crate_type = "proc-macro"]
#![recursion_limit = "128"]

#[macro_use]
extern crate failure;
extern crate proc_macro;
extern crate proc_macro2;
#[macro_use]
extern crate quote;
extern crate byteorder;
extern crate itertools;
extern crate regex;
extern crate syn;

use std::error::Error as StdError;
use std::fmt;
use std::result::Result as StdResult;

use byteorder::NativeEndian;
use failure::Error;
use proc_macro2::Span;
use quote::{ToTokens, TokenStreamExt};
use regex::Regex;

type Result<T> = StdResult<T, Error>;

/// Derives `Packet` with internal attributes.
#[proc_macro_derive(Packet, attributes(payload, construct_with, length, length_fn))]
pub fn packet(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    syn::parse(input)
        .map_err(|err| err.into())
        .and_then(|input| make_packets(input))
        .map(|packets| {
            let mut ts = proc_macro2::TokenStream::new();
            ts.append_all(packets);
            ts
        })
        .unwrap_or_else(compile_error)
        .into()
}

fn compile_error(err: Error) -> proc_macro2::TokenStream {
    let message = format!("err {}\n{}", err, err.backtrace());

    quote! {
        compile_error!(#message);
    }
}

fn make_packets(input: syn::DeriveInput) -> Result<Vec<Packet>> {
    let name = input.ident;

    match input.vis {
        syn::Visibility::Public(_) => {}
        _ => bail!("#[packet] structs/enums {} must be public", name),
    }

    match input.data {
        syn::Data::Struct(s) => make_packet(name, s.fields).map(|packet| vec![packet]),
        syn::Data::Enum(e) => e
            .variants
            .into_iter()
            .map(|v| make_packet(v.ident, v.fields))
            .collect(),
        syn::Data::Union(_) => unimplemented!(),
    }
}

fn make_packet(ident: syn::Ident, fields: syn::Fields) -> Result<Packet> {
    let packet_fields = match fields {
        syn::Fields::Named(fields) => fields,
        _ => bail!("{} all fields in a packet must be named", ident),
    };

    let mut fields = vec![];
    let mut has_payload = false;

    for field in packet_fields.named {
        let mut is_payload = false;
        let mut packet_length = None;
        let mut construct_with = vec![];

        for attr in field.attrs {
            match attr.interpret_meta() {
                Some(syn::Meta::Word(ref ident)) if ident == "payload" => {
                    if has_payload {
                        bail!("packet may not have multiple payloads")
                    }

                    has_payload = true;
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
                    match lit {
                        syn::Lit::Str(lit) => packet_length = Some(lit.value()),
                        syn::Lit::Int(lit) => packet_length = Some(lit.value().to_string()),
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    }
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length_fn" =>
                {
                    match lit {
                        syn::Lit::Str(lit) => {
                            packet_length = Some(lit.value() + "(&_self.to_immutable())")
                        }
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    }
                }
                _ => bail!("unknown attribute {}", attr.into_token_stream()),
            }
        }

        fields.push(Field {
            ident: field.ident.unwrap(),
            ty: field.ty,
            is_payload,
            construct_with: if construct_with.is_empty() {
                None
            } else {
                Some(construct_with)
            },
        })
    }

    if !has_payload {
        bail!("#[packet]'s must contain a payload")
    }

    Ok(Packet { ident, fields })
}

struct Packet {
    ident: syn::Ident,
    fields: Vec<Field>,
}

impl Packet {
    fn base_name(&self) -> &syn::Ident {
        &self.ident
    }

    fn immutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(&format!("{}Packet", self.base_name()), Span::call_site())
    }

    fn mutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(
            &format!("Mutable{}Packet", self.base_name()),
            Span::call_site(),
        )
    }

    fn packet_name(&self, mutable: bool) -> syn::Ident {
        if mutable {
            self.mutable_packet_name()
        } else {
            self.immutable_packet_name()
        }
    }

    fn packet_data(&self, mutable: bool) -> syn::Ident {
        syn::Ident::new(
            if mutable {
                "MutPacketData"
            } else {
                "PacketData"
            },
            Span::call_site(),
        )
    }

    fn generate_packet(&self) -> proc_macro2::TokenStream {
        quote!{}
    }

    fn generate_packet_struct(&self, mutable: bool) -> proc_macro2::TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        quote! {
            /// A structure enabling manipulation of on the wire packets
            #[derive(PartialEq)]
            pub struct #packet_name<'p> {
                packet: ::pnet_macros_support::packet:: #packet_data<'p>,
            }
        }
    }

    fn generate_constructor_new(&self, mutable: bool) -> proc_macro2::TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        let comment = format!(
            "Constructs a new {}.
If the provided buffer is less than the minimum required packet size, this will return None.",
            packet_name
        );
        let mut_ = if mutable {
            Some(syn::Ident::new("mut", Span::call_site()))
        } else {
            None
        };

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn new<'p>(packet: &'p #mut_ [u8]) -> Option<#packet_name<'p>> {
                if packet.len() >= #packet_name::minimum_packet_size() {
                    use ::pnet_macros_support::packet:: #packet_data;
                    Some(#packet_name { packet: #packet_data::Borrowed(packet) })
                } else {
                    None
                }
            }
        }
    }

    fn generate_constructor_owned(&self, mutable: bool) -> proc_macro2::TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        let comment = format!(
            "Constructs a new {0}.
If the provided buffer is less than the minimum required packet size,
this will return None. With this constructor the {0} will own its own data
and the underlying buffer will be dropped when the {0} is.",
            packet_name
        );

        quote! {
            #[doc = #comment]
            pub fn owned(packet: Vec<u8>) -> Option<#packet_name<'static>> {
                if packet.len() >= #packet_name::minimum_packet_size() {
                    use ::pnet_macros_support::packet::#packet_data;
                    Some(#packet_name { packet: #packet_data::Owned(packet) })
                } else {
                    None
                }
            }
        }
    }

    fn generate_to_immutable(&self) -> proc_macro2::TokenStream {
        let immutable_packet_name = self.immutable_packet_name();
        let mutable_packet_name = self.mutable_packet_name();

        let comment = format!(
            "Maps from a {} to a {}",
            mutable_packet_name, immutable_packet_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn to_immutable<'p>(&'p self) -> #immutable_packet_name<'p> {
                use ::pnet_macros_support::packet::PacketData;
                #immutable_packet_name { packet: PacketData::Borrowed(self.packet.as_slice()) }
            }
        }
    }

    fn generate_consume_to_immutable(&self) -> proc_macro2::TokenStream {
        let immutable_packet_name = self.immutable_packet_name();
        let mutable_packet_name = self.mutable_packet_name();

        let comment = format!(
            "Maps from a {} to a {} while consuming the source",
            mutable_packet_name, immutable_packet_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn consume_to_immutable(self) -> #immutable_packet_name<'a> {
                #immutable_packet_name { packet: self.packet.to_immutable() }
            }
        }
    }

    fn generate_minimum_packet_size(&self, bytes_size: usize) -> proc_macro2::TokenStream {
        quote! {
            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub fn minimum_packet_size() -> usize {
                #bytes_size
            }
        }
    }

    fn generate_packet_size(&self, struct_size: usize) -> proc_macro2::TokenStream {
        let base_name = self.base_name();

        let comment = format!(
            "The size (in bytes) of a {} instance when converted into a byte-array",
            base_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn packet_size(_packet: &#base_name) -> usize {
                #struct_size
            }
        }
    }

    fn generate_populate(&self) -> proc_macro2::TokenStream {
        let base_name = self.base_name();

        let comment = format!(
            "Populates a {} using a {} structure",
            self.mutable_packet_name(),
            base_name
        );

        let set_fields = self.fields.iter().map(|field| {
            let field_name = &field.ident;
            let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

            quote! {
                self.#set_field(packet.#field_name);
            }
        });

        quote! {
            #[doc = #comment]
            #[inline]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn populate(&mut self, packet: &#base_name) {
                #(#set_fields)*
            }
        }
    }
}

impl ToTokens for Packet {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let base_name = &self.ident;
        let immutable_packet_name = self.immutable_packet_name();
        let mutable_packet_name = self.mutable_packet_name();

        tokens.append_all([false, true].into_iter().map(|&mutable| {
            let packet_name = self.packet_name(mutable);
            let packet_struct = self.generate_packet_struct(mutable);

            let (accessors, bits_offset) = self.fields.iter().fold(
                (vec![], 0),
                |(mut accessors, mut bits_offset), field| {
                    accessors.push(field.generate_accessor(&mut bits_offset));

                    (accessors, bits_offset)
                },
            );
            let mut mutators = if mutable {
                let (mutators, _) = self.fields.iter().fold(
                    (vec![], 0),
                    |(mut mutators, mut bits_offset), field| {
                        mutators.push(field.generate_mutator(&mut bits_offset));

                        (mutators, bits_offset)
                    },
                );

                mutators
            } else {
                vec![]
            };

            let new = self.generate_constructor_new(mutable);
            let owned = self.generate_constructor_owned(mutable);
            let to_immutable = if mutable {
                Some(self.generate_to_immutable())
            } else {
                None
            };
            let consume_to_immutable = if mutable {
                Some(self.generate_consume_to_immutable())
            } else {
                None
            };
            let minimum_packet_size = self.generate_minimum_packet_size((bits_offset + 7) / 8);
            let packet_size = self.generate_packet_size(0);
            let populate = if mutable {
                Some(self.generate_populate())
            } else {
                None
            };

            quote! {
                #packet_struct

                impl<'a> #packet_name<'a> {
                    #new

                    #owned

                    #to_immutable

                    #consume_to_immutable

                    #minimum_packet_size

                    #packet_size

                    #populate

                    #(#accessors)*

                    #(#mutators)*
                }
            }
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Endianness {
    Little,
    Big,
}

impl Endianness {
    pub fn name(&self) -> &'static str {
        match self {
            Endianness::Little => "little",
            Endianness::Big => "big",
        }
    }
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

struct Field {
    ident: syn::Ident,
    ty: syn::Type,
    construct_with: Option<Vec<syn::Ident>>,
    is_payload: bool,
}

impl Field {
    fn as_primitive(&self) -> Option<(usize, Option<Endianness>)> {
        match self.ty {
            syn::Type::Path(syn::TypePath {
                path: syn::Path { ref segments, .. },
                ..
            }) if segments.len() == 1 =>
            {
                parse_ty(&segments.last()?.value().ident.to_string())
            }
            _ => None,
        }
    }

    fn as_vec(&self) -> Option<(usize, Option<Endianness>)> {
        match self.ty {
            syn::Type::Path(syn::TypePath {
                path: syn::Path { ref segments, .. },
                ..
            }) if segments.len() == 1 && segments.last()?.value().ident == "Vec" =>
            {
                match segments.last()?.value().arguments {
                    syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                        ref args,
                        ..
                    }) if args.len() == 1 =>
                    {
                        match args.last()?.value() {
                            syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
                                path: syn::Path { segments, .. },
                                ..
                            })) if segments.len() == 1 =>
                            {
                                parse_ty(&segments.last()?.value().ident.to_string())
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn generate_accessor(&self, bits_offset: &mut usize) -> proc_macro2::TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;

        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());

        if let Some((bits_size, endianess)) = self.as_primitive() {
            let endianess_name = endianess.map_or("host", |e| e.name());
            let comment = format!(
                        "Get the {} field.
This field is always stored in {} endianess within the struct, but this accessor returns host order.",
                        field_name, endianess_name
                    );
            let read_ops = read_operations(*bits_offset, bits_size, endianess);

            *bits_offset += bits_size;

            quote! {
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #get_field(&self) -> #field_ty {{
                    #(#read_ops)*
                }}
            }
        } else if let Some((item_size, endianess)) = self.as_vec() {
            quote!{}
        } else {
            let ctor = if let Some(ref arg_types) = self.construct_with {
                let mut args = vec![];

                for (idx, arg_ty) in arg_types.iter().enumerate() {
                    let (bits_size, endianess) = parse_ty(&arg_ty.to_string())
                        .expect("arguments to #[construct_with] must be primitives");

                    let read_ops = read_operations(*bits_offset, bits_size, endianess);

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
    }

    fn generate_mutator(&self, bits_offset: &mut usize) -> proc_macro2::TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;

        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

        if let Some((bits_size, endianess)) = self.as_primitive() {
            let endianess_name = endianess.map_or("host", |e| e.name());
            let comment = format!(
                            "Set the {} field.
    This field is always stored in {} endianess within the struct, but this accessor returns host order.",
                            field_name, endianess_name
                        );
            let write_ops = write_operations(
                *bits_offset,
                bits_size,
                endianess,
                syn::Ident::new("val", Span::call_site()),
            );

            *bits_offset += bits_size;

            quote! {
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #set_field(&mut self, val: #field_ty) {{
                    #(#write_ops)*
                }}
            }
        } else if let Some((item_size, endianess)) = self.as_vec() {
            quote!{}
        } else {
            let setter = if let Some(ref arg_types) = self.construct_with {
                let mut set_args = vec![];

                for (idx, arg_ty) in arg_types.iter().enumerate() {
                    let (bits_size, endianess) = parse_ty(&arg_ty.to_string())
                        .expect("arguments to #[construct_with] must be primitives");

                    let write_ops =
                        write_operations(*bits_offset, bits_size, endianess, quote!{ vals.#idx });

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
            let comment = format!("Set the value of the {} field", field_name);

            quote! {
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #set_field(&mut self, val: #field_ty) {{
                    use pnet_macros_support::packet::PrimitiveValues;

                    let vals = val.to_primitive_values();

                    #setter
                }}
            }
        }
    }
}

impl ToTokens for Field {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {}
}

fn parse_ty(ty: &str) -> Option<(usize, Option<Endianness>)> {
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let m = re.captures_iter(ty).next()?;
    let size = m.get(1)?.as_str().parse().ok()?;
    let endianess = match m.get(2).map(|m| m.as_str()) {
        Some("le") => Some(Endianness::Little),
        Some("be") | None => Some(Endianness::Big),
        Some("he") => None,
        _ => return None,
    };

    Some((size, endianess))
}

fn read_operations(
    bits_offset: usize,
    bits_size: usize,
    endianess: Option<Endianness>,
) -> proc_macro2::TokenStream {
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
                self.packet[#bytes_offset]
            },
            16 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u16(&self.packet[#bytes_offset..])
            },
            24 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u24(&self.packet[#bytes_offset..])
            },
            32 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u32(&self.packet[#bytes_offset..])
            },
            48 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u48(&self.packet[#bytes_offset..])
            },
            64 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_u64(&self.packet[#bytes_offset..])
            },
            _ => quote!{
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::read_uint(&self.packet[#bytes_offset..], #bits_size / 8)
            },
        }
    } else {
        quote!{}
    }
}

fn write_operations<T: ToTokens>(
    bits_offset: usize,
    bits_size: usize,
    endianess: Option<Endianness>,
    val: T,
) -> proc_macro2::TokenStream {
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
                self.packet[#bytes_offset] = #val;
            },
            16 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u16(&mut self.packet[#bytes_offset..], #val);
            },
            24 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u24(&mut self.packet[#bytes_offset..], #val);
            },
            32 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u32(&mut self.packet[#bytes_offset..], #val);
            },
            48 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u48(&mut self.packet[#bytes_offset..], #val);
            },
            64 => quote! {
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_u64(&mut self.packet[#bytes_offset..], #val);
            },
            _ => quote!{
                <::byteorder:: #endianess_name as ::byteorder::ByteOrder>::write_uint(&mut self.packet[#bytes_offset..], #bits_size / 8, #val);
            },
        }
    } else {
        quote!{}
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_as_primitive() {
        assert_eq!(parse_ty("u8"), Some((8, Some(Endianness::Big))));
        assert_eq!(parse_ty("u21be"), Some((21, Some(Endianness::Big))));
        assert_eq!(parse_ty("u21le"), Some((21, Some(Endianness::Little))));
        assert_eq!(parse_ty("u21he"), Some((21, None)));
        assert_eq!(parse_ty("u9"), Some((9, Some(Endianness::Big))));
        assert_eq!(parse_ty("u16"), Some((16, Some(Endianness::Big))));
        assert_eq!(parse_ty("uable"), None);
        assert_eq!(parse_ty("u21re"), None);
        assert_eq!(parse_ty("i21be"), None);
    }
}
