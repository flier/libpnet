use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::{self, spanned::Spanned};

use field::Field;
use types::Result;

pub fn parse(input: syn::DeriveInput) -> Result<Vec<Packet>> {
    let name = input.ident;

    match input.vis {
        syn::Visibility::Public(_) => {}
        _ => bail!("#[packet] structs/enums {} must be public", name),
    }

    match input.data {
        syn::Data::Struct(s) => Packet::parse(name, s.fields).map(|packet| vec![packet]),
        syn::Data::Enum(e) => e
            .variants
            .into_iter()
            .map(|v| Packet::parse(v.ident, v.fields))
            .collect(),
        syn::Data::Union(_) => unimplemented!(),
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
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

    fn parse(ident: syn::Ident, fields: syn::Fields) -> Result<Packet> {
        if let syn::Fields::Named(fields) = fields {
            let fields = fields
                .named
                .into_iter()
                .map(Field::parse)
                .collect::<Result<Vec<_>>>()?;

            if fields.iter().rev().skip(1).any(|field| {
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.is_none() && field.is_payload())
                    .unwrap_or_default()
            }) {
                bail!("#[payload] must specify a #[length] or #[length_fn] attribute, unless it is the last field of a packet")
            }

            match fields.iter().filter(|field| field.is_payload()).count() {
                0 => bail!("#[packet] must contain a payload field"),
                1 => Ok(Packet { ident, fields }),
                _ => bail!("#[packet] may not have multiple payloads"),
            }
        } else {
            bail!("{} all fields in a packet must be named", ident)
        }
    }

    fn generate_packet(&self, mutable: bool) -> TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_struct = self.generate_packet_struct(mutable);

        let (accessors, bits_offset) = self.fields.iter().fold(
            (vec![], 0),
            |(mut accessors, mut bits_offset), field| {
                accessors.push(field.generate_accessor(mutable, &mut bits_offset));

                (accessors, bits_offset)
            },
        );
        let mutators = if mutable {
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
        let to_immutable = self.generate_to_immutable();
        let consume_to_immutable = self.generate_consume_to_immutable();
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
    }

    fn generate_packet_struct(&self, mutable: bool) -> TokenStream {
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

    fn generate_constructor_new(&self, mutable: bool) -> TokenStream {
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

    fn generate_constructor_owned(&self, mutable: bool) -> TokenStream {
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

    fn generate_to_immutable(&self) -> TokenStream {
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

    fn generate_consume_to_immutable(&self) -> TokenStream {
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

    fn generate_minimum_packet_size(&self, bytes_size: usize) -> TokenStream {
        quote! {
            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub fn minimum_packet_size() -> usize {
                #bytes_size
            }
        }
    }

    fn generate_packet_size(&self, struct_size: usize) -> TokenStream {
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

    fn generate_populate(&self) -> TokenStream {
        let base_name = self.base_name();

        let comment = format!(
            "Populates a {} using a {} structure",
            self.mutable_packet_name(),
            base_name
        );

        let set_fields = self.fields.iter().map(|field| {
            let field_name = &field.name();
            let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

            if field.as_vec().is_some() {
                quote! {
                    self.#set_field(&packet.#field_name);
                }
            } else {
                quote! {
                    self.#set_field(packet.#field_name);
                }
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
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(&[self.generate_packet(false), self.generate_packet(true)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_struct() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            struct Foo{
                bar: Vec<u8>,
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] structs/enums Foo must be public"
        );
    }

    #[test]
    fn test_payload_field_without_length_in_middle() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                #[payload]
                bar: Vec<u8>,

                payload: Vec<u8>
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "variable length field must have #[length] or #[length_fn] attribute"
        );
    }

    #[test]
    fn test_packet_without_payload() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                bar: u8
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] must contain a payload field"
        );
    }

    #[test]
    fn test_packet_with_multi_payload() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                #[payload]
                foo: Bar,

                #[payload]
                bar: Vec<u8>,
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] may not have multiple payloads"
        );
    }
}
