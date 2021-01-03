// Code generated by machine generator; DO NOT EDIT.

//! Utility for rfc4849 packet.
//!
//! This module handles the packet according to the following definition:
//! ```text
//! //! # -*- text -*-
//! # Copyright (C) 2020 The FreeRADIUS Server project and contributors
//! # This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0
//! # Version $Id$
//! #
//! #	Attributes and values defined in RFC 4849.
//! #	http://www.ietf.org/rfc/rfc4849.txt
//! #
//! #	$Id$
//! #
//! ATTRIBUTE	NAS-Filter-Rule				92	string
//! ```

use crate::core::avp::{AVPError, AVPType, AVP};
use crate::core::packet::Packet;

pub const NAS_FILTER_RULE_TYPE: AVPType = 92;
/// Delete all of `nas_filter_rule` values from a packet.
pub fn delete_nas_filter_rule(packet: &mut Packet) {
    packet.delete(NAS_FILTER_RULE_TYPE);
}
/// Add `nas_filter_rule` string value to a packet.
pub fn add_nas_filter_rule(packet: &mut Packet, value: &str) {
    packet.add(AVP::from_string(NAS_FILTER_RULE_TYPE, value));
}
/// Lookup a `nas_filter_rule` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `nas_filter_rule`, it returns `None`.
pub fn lookup_nas_filter_rule(packet: &Packet) -> Option<Result<String, AVPError>> {
    packet
        .lookup(NAS_FILTER_RULE_TYPE)
        .map(|v| v.encode_string())
}
/// Lookup all of the `nas_filter_rule` string value from a packet.
pub fn lookup_all_nas_filter_rule(packet: &Packet) -> Result<Vec<String>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(NAS_FILTER_RULE_TYPE) {
        vec.push(avp.encode_string()?)
    }
    Ok(vec)
}
