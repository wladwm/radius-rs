// Code generated by machine generator; DO NOT EDIT.

//! Utility for rfc2866 packet.
//!
//! This module handles the packet according to the following definition:
//! ```text
//! //! # -*- text -*-
//! # Copyright (C) 2020 The FreeRADIUS Server project and contributors
//! # This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0
//! # Version $Id$
//! #
//! #	Attributes and values defined in RFC 2866.
//! #	http://www.ietf.org/rfc/rfc2866.txt
//! #
//! #	$Id$
//! #
//! ATTRIBUTE	Acct-Status-Type			40	integer
//! ATTRIBUTE	Acct-Delay-Time				41	integer
//! ATTRIBUTE	Acct-Input-Octets			42	integer
//! ATTRIBUTE	Acct-Output-Octets			43	integer
//! ATTRIBUTE	Acct-Session-Id				44	string
//! ATTRIBUTE	Acct-Authentic				45	integer
//! ATTRIBUTE	Acct-Session-Time			46	integer
//! ATTRIBUTE	Acct-Input-Packets			47	integer
//! ATTRIBUTE	Acct-Output-Packets			48	integer
//! ATTRIBUTE	Acct-Terminate-Cause			49	integer
//! ATTRIBUTE	Acct-Multi-Session-Id			50	string
//! ATTRIBUTE	Acct-Link-Count				51	integer
//!
//! #	Accounting Status Types
//!
//! VALUE	Acct-Status-Type		Start			1
//! VALUE	Acct-Status-Type		Stop			2
//! VALUE	Acct-Status-Type		Alive			3   # dup
//! VALUE	Acct-Status-Type		Interim-Update		3
//! VALUE	Acct-Status-Type		Accounting-On		7
//! VALUE	Acct-Status-Type		Accounting-Off		8
//! VALUE	Acct-Status-Type		Failed			15
//!
//! #	Authentication Types
//!
//! VALUE	Acct-Authentic			RADIUS			1
//! VALUE	Acct-Authentic			Local			2
//! VALUE	Acct-Authentic			Remote			3
//! VALUE	Acct-Authentic			Diameter		4
//!
//! #	Acct Terminate Causes
//!
//! VALUE	Acct-Terminate-Cause		User-Request		1
//! VALUE	Acct-Terminate-Cause		Lost-Carrier		2
//! VALUE	Acct-Terminate-Cause		Lost-Service		3
//! VALUE	Acct-Terminate-Cause		Idle-Timeout		4
//! VALUE	Acct-Terminate-Cause		Session-Timeout		5
//! VALUE	Acct-Terminate-Cause		Admin-Reset		6
//! VALUE	Acct-Terminate-Cause		Admin-Reboot		7
//! VALUE	Acct-Terminate-Cause		Port-Error		8
//! VALUE	Acct-Terminate-Cause		NAS-Error		9
//! VALUE	Acct-Terminate-Cause		NAS-Request		10
//! VALUE	Acct-Terminate-Cause		NAS-Reboot		11
//! VALUE	Acct-Terminate-Cause		Port-Unneeded		12
//! VALUE	Acct-Terminate-Cause		Port-Preempted		13
//! VALUE	Acct-Terminate-Cause		Port-Suspended		14
//! VALUE	Acct-Terminate-Cause		Service-Unavailable	15
//! VALUE	Acct-Terminate-Cause		Callback		16
//! VALUE	Acct-Terminate-Cause		User-Error		17
//! VALUE	Acct-Terminate-Cause		Host-Request		18
//! ```

use crate::core::avp::{AVPError, AVPType, AVP};
use crate::core::packet::Packet;

pub const ACCT_STATUS_TYPE_TYPE: AVPType = 40;
/// Delete all of `acct_status_type` values from a packet.
pub fn delete_acct_status_type(packet: &mut Packet) {
    packet.delete(ACCT_STATUS_TYPE_TYPE);
}
/// Add `acct_status_type` value-defined integer value to a packet.
pub fn add_acct_status_type(packet: &mut Packet, value: AcctStatusType) {
    packet.add(AVP::from_u32(ACCT_STATUS_TYPE_TYPE, value as u32));
}
/// Lookup a `acct_status_type` value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_status_type`, it returns `None`.
pub fn lookup_acct_status_type(packet: &Packet) -> Option<Result<AcctStatusType, AVPError>> {
    packet
        .lookup(ACCT_STATUS_TYPE_TYPE)
        .map(|v| Ok(v.encode_u32()? as AcctStatusType))
}
/// Lookup all of the `acct_status_type` value-defined integer value from a packet.
pub fn lookup_all_acct_status_type(packet: &Packet) -> Result<Vec<AcctStatusType>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_STATUS_TYPE_TYPE) {
        vec.push(avp.encode_u32()? as AcctStatusType)
    }
    Ok(vec)
}

pub const ACCT_DELAY_TIME_TYPE: AVPType = 41;
/// Delete all of `acct_delay_time` values from a packet.
pub fn delete_acct_delay_time(packet: &mut Packet) {
    packet.delete(ACCT_DELAY_TIME_TYPE);
}
/// Add `acct_delay_time` integer value to a packet.
pub fn add_acct_delay_time(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_DELAY_TIME_TYPE, value));
}
/// Lookup a `acct_delay_time` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_delay_time`, it returns `None`.
pub fn lookup_acct_delay_time(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet.lookup(ACCT_DELAY_TIME_TYPE).map(|v| v.encode_u32())
}
/// Lookup all of the `acct_delay_time` integer value from a packet.
pub fn lookup_all_acct_delay_time(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_DELAY_TIME_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_INPUT_OCTETS_TYPE: AVPType = 42;
/// Delete all of `acct_input_octets` values from a packet.
pub fn delete_acct_input_octets(packet: &mut Packet) {
    packet.delete(ACCT_INPUT_OCTETS_TYPE);
}
/// Add `acct_input_octets` integer value to a packet.
pub fn add_acct_input_octets(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_INPUT_OCTETS_TYPE, value));
}
/// Lookup a `acct_input_octets` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_input_octets`, it returns `None`.
pub fn lookup_acct_input_octets(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet
        .lookup(ACCT_INPUT_OCTETS_TYPE)
        .map(|v| v.encode_u32())
}
/// Lookup all of the `acct_input_octets` integer value from a packet.
pub fn lookup_all_acct_input_octets(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_INPUT_OCTETS_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_OUTPUT_OCTETS_TYPE: AVPType = 43;
/// Delete all of `acct_output_octets` values from a packet.
pub fn delete_acct_output_octets(packet: &mut Packet) {
    packet.delete(ACCT_OUTPUT_OCTETS_TYPE);
}
/// Add `acct_output_octets` integer value to a packet.
pub fn add_acct_output_octets(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_OUTPUT_OCTETS_TYPE, value));
}
/// Lookup a `acct_output_octets` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_output_octets`, it returns `None`.
pub fn lookup_acct_output_octets(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet
        .lookup(ACCT_OUTPUT_OCTETS_TYPE)
        .map(|v| v.encode_u32())
}
/// Lookup all of the `acct_output_octets` integer value from a packet.
pub fn lookup_all_acct_output_octets(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_OUTPUT_OCTETS_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_SESSION_ID_TYPE: AVPType = 44;
/// Delete all of `acct_session_id` values from a packet.
pub fn delete_acct_session_id(packet: &mut Packet) {
    packet.delete(ACCT_SESSION_ID_TYPE);
}
/// Add `acct_session_id` string value to a packet.
pub fn add_acct_session_id(packet: &mut Packet, value: &str) {
    packet.add(AVP::from_string(ACCT_SESSION_ID_TYPE, value));
}
/// Lookup a `acct_session_id` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_session_id`, it returns `None`.
pub fn lookup_acct_session_id(packet: &Packet) -> Option<Result<String, AVPError>> {
    packet
        .lookup(ACCT_SESSION_ID_TYPE)
        .map(|v| v.encode_string())
}
/// Lookup all of the `acct_session_id` string value from a packet.
pub fn lookup_all_acct_session_id(packet: &Packet) -> Result<Vec<String>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_SESSION_ID_TYPE) {
        vec.push(avp.encode_string()?)
    }
    Ok(vec)
}

pub const ACCT_AUTHENTIC_TYPE: AVPType = 45;
/// Delete all of `acct_authentic` values from a packet.
pub fn delete_acct_authentic(packet: &mut Packet) {
    packet.delete(ACCT_AUTHENTIC_TYPE);
}
/// Add `acct_authentic` value-defined integer value to a packet.
pub fn add_acct_authentic(packet: &mut Packet, value: AcctAuthentic) {
    packet.add(AVP::from_u32(ACCT_AUTHENTIC_TYPE, value as u32));
}
/// Lookup a `acct_authentic` value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_authentic`, it returns `None`.
pub fn lookup_acct_authentic(packet: &Packet) -> Option<Result<AcctAuthentic, AVPError>> {
    packet
        .lookup(ACCT_AUTHENTIC_TYPE)
        .map(|v| Ok(v.encode_u32()? as AcctAuthentic))
}
/// Lookup all of the `acct_authentic` value-defined integer value from a packet.
pub fn lookup_all_acct_authentic(packet: &Packet) -> Result<Vec<AcctAuthentic>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_AUTHENTIC_TYPE) {
        vec.push(avp.encode_u32()? as AcctAuthentic)
    }
    Ok(vec)
}

pub const ACCT_SESSION_TIME_TYPE: AVPType = 46;
/// Delete all of `acct_session_time` values from a packet.
pub fn delete_acct_session_time(packet: &mut Packet) {
    packet.delete(ACCT_SESSION_TIME_TYPE);
}
/// Add `acct_session_time` integer value to a packet.
pub fn add_acct_session_time(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_SESSION_TIME_TYPE, value));
}
/// Lookup a `acct_session_time` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_session_time`, it returns `None`.
pub fn lookup_acct_session_time(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet
        .lookup(ACCT_SESSION_TIME_TYPE)
        .map(|v| v.encode_u32())
}
/// Lookup all of the `acct_session_time` integer value from a packet.
pub fn lookup_all_acct_session_time(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_SESSION_TIME_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_INPUT_PACKETS_TYPE: AVPType = 47;
/// Delete all of `acct_input_packets` values from a packet.
pub fn delete_acct_input_packets(packet: &mut Packet) {
    packet.delete(ACCT_INPUT_PACKETS_TYPE);
}
/// Add `acct_input_packets` integer value to a packet.
pub fn add_acct_input_packets(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_INPUT_PACKETS_TYPE, value));
}
/// Lookup a `acct_input_packets` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_input_packets`, it returns `None`.
pub fn lookup_acct_input_packets(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet
        .lookup(ACCT_INPUT_PACKETS_TYPE)
        .map(|v| v.encode_u32())
}
/// Lookup all of the `acct_input_packets` integer value from a packet.
pub fn lookup_all_acct_input_packets(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_INPUT_PACKETS_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_OUTPUT_PACKETS_TYPE: AVPType = 48;
/// Delete all of `acct_output_packets` values from a packet.
pub fn delete_acct_output_packets(packet: &mut Packet) {
    packet.delete(ACCT_OUTPUT_PACKETS_TYPE);
}
/// Add `acct_output_packets` integer value to a packet.
pub fn add_acct_output_packets(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_OUTPUT_PACKETS_TYPE, value));
}
/// Lookup a `acct_output_packets` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_output_packets`, it returns `None`.
pub fn lookup_acct_output_packets(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet
        .lookup(ACCT_OUTPUT_PACKETS_TYPE)
        .map(|v| v.encode_u32())
}
/// Lookup all of the `acct_output_packets` integer value from a packet.
pub fn lookup_all_acct_output_packets(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_OUTPUT_PACKETS_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub const ACCT_TERMINATE_CAUSE_TYPE: AVPType = 49;
/// Delete all of `acct_terminate_cause` values from a packet.
pub fn delete_acct_terminate_cause(packet: &mut Packet) {
    packet.delete(ACCT_TERMINATE_CAUSE_TYPE);
}
/// Add `acct_terminate_cause` value-defined integer value to a packet.
pub fn add_acct_terminate_cause(packet: &mut Packet, value: AcctTerminateCause) {
    packet.add(AVP::from_u32(ACCT_TERMINATE_CAUSE_TYPE, value as u32));
}
/// Lookup a `acct_terminate_cause` value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_terminate_cause`, it returns `None`.
pub fn lookup_acct_terminate_cause(
    packet: &Packet,
) -> Option<Result<AcctTerminateCause, AVPError>> {
    packet
        .lookup(ACCT_TERMINATE_CAUSE_TYPE)
        .map(|v| Ok(v.encode_u32()? as AcctTerminateCause))
}
/// Lookup all of the `acct_terminate_cause` value-defined integer value from a packet.
pub fn lookup_all_acct_terminate_cause(
    packet: &Packet,
) -> Result<Vec<AcctTerminateCause>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_TERMINATE_CAUSE_TYPE) {
        vec.push(avp.encode_u32()? as AcctTerminateCause)
    }
    Ok(vec)
}

pub const ACCT_MULTI_SESSION_ID_TYPE: AVPType = 50;
/// Delete all of `acct_multi_session_id` values from a packet.
pub fn delete_acct_multi_session_id(packet: &mut Packet) {
    packet.delete(ACCT_MULTI_SESSION_ID_TYPE);
}
/// Add `acct_multi_session_id` string value to a packet.
pub fn add_acct_multi_session_id(packet: &mut Packet, value: &str) {
    packet.add(AVP::from_string(ACCT_MULTI_SESSION_ID_TYPE, value));
}
/// Lookup a `acct_multi_session_id` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_multi_session_id`, it returns `None`.
pub fn lookup_acct_multi_session_id(packet: &Packet) -> Option<Result<String, AVPError>> {
    packet
        .lookup(ACCT_MULTI_SESSION_ID_TYPE)
        .map(|v| v.encode_string())
}
/// Lookup all of the `acct_multi_session_id` string value from a packet.
pub fn lookup_all_acct_multi_session_id(packet: &Packet) -> Result<Vec<String>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_MULTI_SESSION_ID_TYPE) {
        vec.push(avp.encode_string()?)
    }
    Ok(vec)
}

pub const ACCT_LINK_COUNT_TYPE: AVPType = 51;
/// Delete all of `acct_link_count` values from a packet.
pub fn delete_acct_link_count(packet: &mut Packet) {
    packet.delete(ACCT_LINK_COUNT_TYPE);
}
/// Add `acct_link_count` integer value to a packet.
pub fn add_acct_link_count(packet: &mut Packet, value: u32) {
    packet.add(AVP::from_u32(ACCT_LINK_COUNT_TYPE, value));
}
/// Lookup a `acct_link_count` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `acct_link_count`, it returns `None`.
pub fn lookup_acct_link_count(packet: &Packet) -> Option<Result<u32, AVPError>> {
    packet.lookup(ACCT_LINK_COUNT_TYPE).map(|v| v.encode_u32())
}
/// Lookup all of the `acct_link_count` integer value from a packet.
pub fn lookup_all_acct_link_count(packet: &Packet) -> Result<Vec<u32>, AVPError> {
    let mut vec = Vec::new();
    for avp in packet.lookup_all(ACCT_LINK_COUNT_TYPE) {
        vec.push(avp.encode_u32()?)
    }
    Ok(vec)
}

pub type AcctAuthentic = u32;
pub const ACCT_AUTHENTIC_RADIUS: AcctAuthentic = 1;
pub const ACCT_AUTHENTIC_LOCAL: AcctAuthentic = 2;
pub const ACCT_AUTHENTIC_REMOTE: AcctAuthentic = 3;
pub const ACCT_AUTHENTIC_DIAMETER: AcctAuthentic = 4;

pub type AcctStatusType = u32;
pub const ACCT_STATUS_TYPE_START: AcctStatusType = 1;
pub const ACCT_STATUS_TYPE_STOP: AcctStatusType = 2;
pub const ACCT_STATUS_TYPE_ALIVE: AcctStatusType = 3;
pub const ACCT_STATUS_TYPE_INTERIM_UPDATE: AcctStatusType = 3;
pub const ACCT_STATUS_TYPE_ACCOUNTING_ON: AcctStatusType = 7;
pub const ACCT_STATUS_TYPE_ACCOUNTING_OFF: AcctStatusType = 8;
pub const ACCT_STATUS_TYPE_FAILED: AcctStatusType = 15;

pub type AcctTerminateCause = u32;
pub const ACCT_TERMINATE_CAUSE_USER_REQUEST: AcctTerminateCause = 1;
pub const ACCT_TERMINATE_CAUSE_LOST_CARRIER: AcctTerminateCause = 2;
pub const ACCT_TERMINATE_CAUSE_LOST_SERVICE: AcctTerminateCause = 3;
pub const ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT: AcctTerminateCause = 4;
pub const ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT: AcctTerminateCause = 5;
pub const ACCT_TERMINATE_CAUSE_ADMIN_RESET: AcctTerminateCause = 6;
pub const ACCT_TERMINATE_CAUSE_ADMIN_REBOOT: AcctTerminateCause = 7;
pub const ACCT_TERMINATE_CAUSE_PORT_ERROR: AcctTerminateCause = 8;
pub const ACCT_TERMINATE_CAUSE_NAS_ERROR: AcctTerminateCause = 9;
pub const ACCT_TERMINATE_CAUSE_NAS_REQUEST: AcctTerminateCause = 10;
pub const ACCT_TERMINATE_CAUSE_NAS_REBOOT: AcctTerminateCause = 11;
pub const ACCT_TERMINATE_CAUSE_PORT_UNNEEDED: AcctTerminateCause = 12;
pub const ACCT_TERMINATE_CAUSE_PORT_PREEMPTED: AcctTerminateCause = 13;
pub const ACCT_TERMINATE_CAUSE_PORT_SUSPENDED: AcctTerminateCause = 14;
pub const ACCT_TERMINATE_CAUSE_SERVICE_UNAVAILABLE: AcctTerminateCause = 15;
pub const ACCT_TERMINATE_CAUSE_CALLBACK: AcctTerminateCause = 16;
pub const ACCT_TERMINATE_CAUSE_USER_ERROR: AcctTerminateCause = 17;
pub const ACCT_TERMINATE_CAUSE_HOST_REQUEST: AcctTerminateCause = 18;
