use std::cell::RefCell;
use std::ops::Deref;

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn;

use field::{Field, Kind};
use packet::Packet;
use types::{Endianness, Length, ToBytesOffset};

trait Generator {
    fn tokens(&self) -> TokenStream;
}

pub struct PacketGenerator {
    packet: Packet,
    mutable: bool,
}

impl Deref for PacketGenerator {
    type Target = Packet;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl PacketGenerator {
    fn base_name(&self) -> &syn::Ident {
        &self.packet.ident
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

    fn packet_name(&self) -> syn::Ident {
        if self.mutable {
            self.mutable_packet_name()
        } else {
            self.immutable_packet_name()
        }
    }

    fn packet_data(&self) -> syn::Ident {
        syn::Ident::new(
            if self.mutable {
                "MutPacketData"
            } else {
                "PacketData"
            },
            Span::call_site(),
        )
    }
}

impl Generator for PacketGenerator {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.packet_name();

        let (accessors, _) = self.packet.fields.iter().fold(
            (vec![], vec![]),
            |(mut accessors, mut length_funcs), field| {
                accessors.push(FieldAccessor::new(self, field, &length_funcs).tokens());
                if let Some(bits) = field.bits() {
                    length_funcs.push(bits)
                }
                (accessors, length_funcs)
            },
        );

        let (mutators, _) = self.packet.fields.iter().fold(
            (vec![], vec![]),
            |(mut mutators, mut length_funcs), field| {
                mutators.push(FieldMutators(self, field, &length_funcs).tokens());
                if let Some(bits) = field.bits() {
                    length_funcs.push(bits)
                }
                (mutators, length_funcs)
            },
        );

        let bits_length_funcs = self
            .packet
            .fields
            .iter()
            .flat_map(|field| field.bits())
            .collect::<Vec<_>>();
        let struct_length_funcs = self
            .packet
            .fields
            .iter()
            .flat_map(|field| field.len())
            .collect::<Vec<_>>();

        let new = New(self).tokens();
        let owned = Owned(self).tokens();
        let to_immutable = ToImmutable(self).tokens();
        let consume_to_immutable = ConsumeToImmutable(self).tokens();
        let minimum_packet_size = MinimumPacketSize(self, &bits_length_funcs).tokens();
        let packet_size = PacketSize(self, &struct_length_funcs).tokens();
        let populate = Populate(self).tokens();

        quote! {
            impl<'a> #packet_name<'a> {
                #(#accessors)*

                #(#mutators)*

                #new

                #owned

                #to_immutable

                #consume_to_immutable

                #minimum_packet_size

                #packet_size

                #populate
            }
        }
    }
}

struct New<'a>(&'a PacketGenerator);

impl<'a> Generator for New<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.0.packet_name();
        let packet_data = self.0.packet_data();

        let comment = format!(
            "Constructs a new {}.
If the provided buffer is less than the minimum required packet size, this will return None.",
            packet_name
        );
        let mut_ = if self.0.mutable {
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
}

struct Owned<'a>(&'a PacketGenerator);

impl<'a> Generator for Owned<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.0.packet_name();
        let packet_data = self.0.packet_data();

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
}

struct ToImmutable<'a>(&'a PacketGenerator);

impl<'a> Generator for ToImmutable<'a> {
    fn tokens(&self) -> TokenStream {
        let immutable_packet_name = self.0.immutable_packet_name();
        let mutable_packet_name = self.0.mutable_packet_name();

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
}

struct ConsumeToImmutable<'a>(&'a PacketGenerator);

impl<'a> Generator for ConsumeToImmutable<'a> {
    fn tokens(&self) -> TokenStream {
        let immutable_packet_name = self.0.immutable_packet_name();
        let mutable_packet_name = self.0.mutable_packet_name();

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
}

struct MinimumPacketSize<'a>(&'a PacketGenerator, &'a [Length]);

impl<'a> Generator for MinimumPacketSize<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_size = self.1.bytes_offset();

        quote! {
            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub fn minimum_packet_size() -> usize {
                #packet_size
            }
        }
    }
}

struct PacketSize<'a>(&'a PacketGenerator, &'a [Length]);

impl<'a> Generator for PacketSize<'a> {
    fn tokens(&self) -> TokenStream {
        let base_name = self.0.base_name();
        let comment = format!(
            "The size (in bytes) of a {} instance when converted into a byte-array",
            base_name
        );
        let packet_size = self.1.bytes_offset();

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn packet_size(_packet: &#base_name) -> usize {
                #packet_size
            }
        }
    }
}

struct Populate<'a>(&'a PacketGenerator);

impl<'a> Generator for Populate<'a> {
    fn tokens(&self) -> TokenStream {
        let base_name = self.0.base_name();

        let comment = format!(
            "Populates a {} using a {} structure",
            self.0.mutable_packet_name(),
            base_name
        );

        let set_fields = self.0.packet.fields.iter().map(|field| {
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
            pub fn populate(&self, packet: &#base_name) {
                #(#set_fields)*
            }
        }
    }
}

struct FieldAccessor<'a> {
    gen: &'a PacketGenerator,
    field: &'a Field,
    length_funcs: &'a [Length],
}

impl<'a> FieldAccessor<'a> {
    pub fn new(gen: &'a PacketGenerator, field: &'a Field, length_funcs: &'a [Length]) -> Self {
        FieldAccessor {
            gen,
            field,
            length_funcs,
        }
    }
}

impl<'a> Generator for FieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        match self.field.kind {
            Kind::Primitive { bits, endianness } => {
                PrimitiveFieldAccessor::new(self, bits, endianness).tokens()
            }
            Kind::Vec { .. } => VecFieldAccessor(self).tokens(),
            Kind::Custom { .. } => CustomFieldAccessor(self).tokens(),
        }
    }
}

struct PrimitiveFieldAccessor<'a> {
    accessor: &'a FieldAccessor<'a>,
    bits: usize,
    endianness: Option<Endianness>,
}

impl<'a> PrimitiveFieldAccessor<'a> {
    pub fn new(
        accessor: &'a FieldAccessor<'a>,
        bits: usize,
        endianness: Option<Endianness>,
    ) -> Self {
        PrimitiveFieldAccessor {
            accessor,
            bits,
            endianness,
        }
    }
}

impl<'a> Deref for PrimitiveFieldAccessor<'a> {
    type Target = FieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        &self.accessor
    }
}

impl<'a> Generator for PrimitiveFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.field.ident;
        let field_ty = &self.field.ty;
        let comment = format!("Get the {} field.
This field is always stored in {} endianness within the struct, but this accessor returns host order.",
            field_name, self.endianness.map_or("host", |e| e.name())
        );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let read_ops = read_operations(
            self.accessor.length_funcs,
            self.bits,
            self.endianness,
            quote!{ self.packet },
        );

        quote_spanned! { self.field.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> #field_ty {
                #(#read_ops)*
            }
        }
    }
}

struct VecFieldAccessor<'a>(&'a FieldAccessor<'a>);

impl<'a> Generator for VecFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        quote!{}
    }
}

struct CustomFieldAccessor<'a>(&'a FieldAccessor<'a>);

impl<'a> Generator for CustomFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        quote!{}
    }
}

struct FieldMutators<'a>(&'a PacketGenerator, &'a Field, &'a [Length]);

impl<'a> Generator for FieldMutators<'a> {
    fn tokens(&self) -> TokenStream {
        quote!{}
    }
}

pub fn read_operations<O: ToBytesOffset, T: ToTokens>(
    offset: O,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
) -> TokenStream {
    if bits % 8 == 0 && bits <= 64 {
        let bytes_offset = offset.bytes_offset();
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
                let bytes = (bits + 7) / 8;

                quote!{
                    <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_uint(&#packet[#bytes_offset..], #bytes)
                }
            }
        }
    } else {
        unimplemented!()
    }
}

pub fn write_operations<O: ToBytesOffset, T: ToTokens, V: ToTokens>(
    offset: O,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
    val: V,
) -> TokenStream {
    if bits % 8 == 0 && bits <= 64 {
        let bytes_offset = offset.bytes_offset();
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
}
