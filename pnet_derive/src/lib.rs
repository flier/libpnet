#![crate_type = "proc-macro"]
#![recursion_limit = "128"]

extern crate proc_macro;

extern crate proc_macro2;
#[macro_use]
extern crate quote;
extern crate byteorder;
extern crate itertools;
extern crate syn;

use byteorder::NativeEndian;
use proc_macro2::Span;
use quote::{ToTokens, TokenStreamExt};

/// Derives `Packet` with internal attributes.
#[proc_macro_derive(Packet, attributes(payload, construct_with, length, length_fn))]
pub fn packet(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    let name = ast.ident;

    match ast.vis {
        syn::Visibility::Public(_) => {}
        _ => panic!("#[packet] structs/enums {} must be public", name),
    }

    let mut ts = proc_macro2::TokenStream::new();

    match ast.data {
        syn::Data::Struct(s) => ts.append_all(&[make_packet(name, s.fields)]),
        syn::Data::Enum(e) => ts.append_all(
            e.variants
                .into_iter()
                .map(|v| make_packet(v.ident, v.fields)),
        ),
        syn::Data::Union(_) => unimplemented!(),
    };

    ts.into()
}

fn make_packet(ident: syn::Ident, fields: syn::Fields) -> Packet {
    let packet_fields = match fields {
        syn::Fields::Named(fields) => fields,
        _ => panic!("{} all fields in a packet must be named", ident),
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
                    is_payload = true;
                    has_payload = true;
                }
                Some(syn::Meta::List(syn::MetaList {
                    ref ident,
                    ref nested,
                    ..
                })) if ident == "construct_with" =>
                {
                    if nested.is_empty() {
                        panic!("#[construct_with] must have at least one argument")
                    }

                    construct_with.extend(nested.into_iter().map(|meta| match meta {
                        syn::NestedMeta::Meta(syn::Meta::Word(ident)) => ident.clone(),
                        _ => panic!(
                            "#[construct_with] should be of the form #[construct_with(<types>)]"
                        ),
                    }))
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length" =>
                {
                    match lit {
                        syn::Lit::Str(lit) => packet_length = Some(lit.value()),
                        syn::Lit::Int(lit) => packet_length = Some(lit.value().to_string()),
                        _ => panic!("expected attribute to be a string `{} = \"...\"`", ident),
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
                        _ => panic!("expected attribute to be a string `{} = \"...\"`", ident),
                    }
                }
                _ => panic!("unknown attribute {}", attr.into_token_stream()),
            }
        }

        fields.push(Field {
            ident: field.ident.unwrap(),
            ty: field.ty,
            is_payload,
        })
    }

    if !has_payload {
        panic!("#[packet]'s must contain a payload")
    }

    Packet { ident, fields }
}

struct Packet {
    ident: syn::Ident,
    fields: Vec<Field>,
}

impl Packet {}

impl ToTokens for Packet {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let base_name = &self.ident;
        let immutable_packet_name =
            syn::Ident::new(&format!("{}Packet", self.ident), Span::call_site());
        let mutable_packet_name =
            syn::Ident::new(&format!("Mutable{}Packet", self.ident), Span::call_site());

        let mut bit_offset = 0usize;

        tokens.append_all([true, false].into_iter().map(|&mutable| {
            let packet_name = if mutable {
                &mutable_packet_name
            } else {
                &immutable_packet_name
            };
            let packet_data = syn::Ident::new(
                if mutable {
                    "MutPacketData"
                } else {
                    "PacketData"
                },
                Span::call_site(),
            );
            let mut_ = if mutable {
                Some(syn::Ident::new("mut", Span::call_site()))
            } else {
                None
            };

            let accessors = self.fields.iter().map(|field| {
                let field_name = &field.ident;
                let field_ty = &field.ty;
                let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
                let endian = "";

                let comment = format!(
                    "Get the {} field.
This field is always stored {} within the struct, but this accessor returns host order.",
                    field_name, endian
                );

                quote! {
                    #[doc = #comment]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn #get_field(&self) -> #field_ty {{
                    }}
                }
            });

            let mutators = self.fields.iter().map(|field| {
                let field_name = &field.ident;
                let field_ty = &field.ty;
                let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
                let endian = "";

                let comment = format!(
                    "Set the {} field.
This field is always stored {} within the struct, but this accessor returns host order.",
                    field_name, endian
                );

                quote! {
                    #[doc = #comment]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn #set_field(&mut self, val: #field_ty) {{
                    }}
                }
            });

            let set_fields = self.fields.iter().map(|field| {
                let field_name = &field.ident;
                let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

                quote! {
                    self.#set_field(&packet.#field_name);
                }
            });

            let new = {
                let comment = format!(
                    "Constructs a new {}.
If the provided buffer is less than the minimum required packet size, this will return None.",
                    packet_name
                );

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
            };

            let owned = {
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
            };

            let to_immutable = {
                let comment = format!("Maps from a {} to a {}", packet_name, immutable_packet_name);

                quote! {
                    #[doc = #comment]
                    #[inline]
                    pub fn to_immutable<'p>(&'p self) -> #immutable_packet_name<'p> {
                        use ::pnet_macros_support::packet::PacketData;
                        #immutable_packet_name { packet: PacketData::Borrowed(self.packet.as_slice()) }
                    }
                }
            };

            let consume_to_immutable = {
                let comment = format!(
                    "Maps from a {} to a {} while consuming the source",
                    packet_name, immutable_packet_name
                );

                quote! {
                    #[doc = #comment]
                    #[inline]
                    pub fn consume_to_immutable(self) -> #immutable_packet_name<'a> {
                        #immutable_packet_name { packet: self.packet.to_immutable() }
                    }
                }
            };

            let minimum_packet_size = {
                let byte_size = (bit_offset + 7) / 8;

                quote! {
                    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
                    /// of the fixed-size fields.
                    #[inline]
                    pub fn minimum_packet_size() -> usize {
                        #byte_size
                    }
                }
            };

            let packet_size = {
                let mut struct_size = 0usize;
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
            };

            let populate = {
                let comment = format!(
                    "Populates a {} using a {} structure",
                    packet_name, base_name
                );

                quote! {
                    #[doc = #comment]
                    #[inline]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn populate(&mut self, packet: &#base_name) {
                        #(#set_fields)*
                    }
                }
            };

            quote! {
                /// A structure enabling manipulation of on the wire packets
                #[derive(PartialEq)]
                pub struct #packet_name<'p> {
                    packet: ::pnet_macros_support::packet:: #packet_data<'p>,
                }

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

struct Field {
    ident: syn::Ident,
    ty: syn::Type,
    is_payload: bool,
}

impl ToTokens for Field {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {}
}
