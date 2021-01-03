// Code generated by machine generator; DO NOT EDIT.

//! Utility for rfc4675 packet.
//!
//! This module handles the packet according to the following definition:
//! ```text
//! //! # -*- text -*-
//! # Copyright (C) 2020 The FreeRADIUS Server project and contributors
//! # This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0
//! # Version $Id$
//! #
//! #	Attributes and values defined in RFC 4675.
//! #	http://www.ietf.org/rfc/rfc4675.txt
//! #
//! #	$Id$
//! #
//!
//! #
//! #  High byte = '1' (0x31) means the frames are tagged.
//! #  High byte = '2' (0x32) means the frames are untagged.
//! #
//! #  Next 12 bits MUST be zero.
//! #
//! #  Lower 12 bits is the IEEE-802.1Q VLAN VID.
//! #
//! ATTRIBUTE	Egress-VLANID				56	integer
//! ATTRIBUTE	Ingress-Filters				57	integer
//!
//! #
//! #  First byte == '1' (0x31) means that the frames are tagged.
//! #  First byte == '2' (0x32) means that the frames are untagged.
//! #
//! ATTRIBUTE	Egress-VLAN-Name			58	string
//! ATTRIBUTE	User-Priority-Table			59	octets
//!
//! VALUE	Ingress-Filters			Enabled			1
//! VALUE	Ingress-Filters			Disabled		2
//! ```

use crate::core::avp::{AVPError, AVPType, AVP};
use crate::core::packet::Packet;

pub const EGRESS_VLANID_TYPE: AVPType = 56;
/// Delete all of `egress_vlanid` values from a packet.
pub fn delete_egress_vlanid(packet: &mut Packet) {
    packet.delete(EGRESS_VLANID_TYPE);
}
/// Add `egress_vlanid` integer value to a packet.
pub fn add_egress_vlanid(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(EGRESS_VLANID_TYPE, value));
}
/// Lookup a `egress_vlanid` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `egress_vlanid`, it returns `None`.
pub fn lookup_egress_vlanid(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet.lookup(EGRESS_VLANID_TYPE).map(|v| v.encode_u32())
}
/// Lookup all of the `egress_vlanid` integer value from a packet.
pub fn lookup_all_egress_vlanid(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(EGRESS_VLANID_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const INGRESS_FILTERS_TYPE: AVPType = 57;
/// Delete all of `ingress_filters` values from a packet.
pub fn delete_ingress_filters(packet: &mut Packet) {
    packet.delete(INGRESS_FILTERS_TYPE);
}
/// Add `ingress_filters` value-defined integer value to a packet.
pub fn add_ingress_filters(packet: &mut Packet, value: IngressFilters) {
    packet.add(AVP::from_u32(INGRESS_FILTERS_TYPE, value as u32));
}
/// Lookup a `ingress_filters` value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `ingress_filters`, it returns `None`.
pub fn lookup_ingress_filters(packet: &Packet) -> Option<Result<IngressFilters, AVPError>> {
    packet
        .lookup(INGRESS_FILTERS_TYPE)
        .map(|v| Ok(v.encode_u32()? as IngressFilters))
}
/// Lookup all of the `ingress_filters` value-defined integer value from a packet.
pub fn lookup_all_ingress_filters(packet: &Packet) -> Result<Vec<IngressFilters>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(INGRESS_FILTERS_TYPE) {
        vec.push(avp.encode_u32()? as IngressFilters)
    }
    Ok(vec)
}

pub const EGRESS_VLAN_NAME_TYPE: AVPType = 58;
/// Delete all of `egress_vlan_name` values from a packet.
pub fn delete_egress_vlan_name(packet: &mut Packet) {
    packet.delete(EGRESS_VLAN_NAME_TYPE);
}
/// Add `egress_vlan_name` string value to a packet.
pub fn add_egress_vlan_name(packet: &mut Packet, value: &str) {
    packet.add(AVP::from_string(EGRESS_VLAN_NAME_TYPE, value));
}
/// Lookup a `egress_vlan_name` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `egress_vlan_name`, it returns `None`.
pub fn lookup_egress_vlan_name(packet: &Packet) -> Option<Result<String, AVPError>> {
    packet
        .lookup(EGRESS_VLAN_NAME_TYPE)
        .map(|v| v.encode_string())
}
/// Lookup all of the `egress_vlan_name` string value from a packet.
pub fn lookup_all_egress_vlan_name(packet: &Packet) -> Result<Vec<String>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(EGRESS_VLAN_NAME_TYPE) {
        vec.push(avp.encode_string()?)
    }
    Ok(vec)
}

pub const USER_PRIORITY_TABLE_TYPE: AVPType = 59;
/// Delete all of `user_priority_table` values from a packet.
pub fn delete_user_priority_table(packet: &mut Packet) {
    packet.delete(USER_PRIORITY_TABLE_TYPE);
}
/// Add `user_priority_table` octets value to a packet.
pub fn add_user_priority_table(packet: &mut Packet, value: &[u8]) {
    packet.add(AVP::from_bytes(USER_PRIORITY_TABLE_TYPE, value));
}
/// Lookup a `user_priority_table` octets value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `user_priority_table`, it returns `None`.
pub fn lookup_user_priority_table(packet: &Packet) -> Option<Vec<u8>> {
    packet
        .lookup(USER_PRIORITY_TABLE_TYPE)
        .map(|v| v.encode_bytes())
}
/// Lookup all of the `user_priority_table` octets value from a packet.
pub fn lookup_all_user_priority_table(packet: &Packet) -> Vec<Vec<u8>> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(USER_PRIORITY_TABLE_TYPE) {
        vec.push(avp.encode_bytes())
    }
    vec
}

pub type IngressFilters = u32;
pub const INGRESS_FILTERS_ENABLED: IngressFilters = 1;
pub const INGRESS_FILTERS_DISABLED: IngressFilters = 2;
