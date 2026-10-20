#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 d-malinowski
//
// rrb-unifi: translate 802.11r RRB-OUI frames (ethertype 0x88b7) between the
// upstream hostapd framing used by OpenWRT and the UniFi framing.
//
//   upstream: OUI(00 13 74 00 01) | type | auth_len | auth TLVs | AES-SIV data
//   UniFi:    OUI(00 13 74 00 01) | type | src AP(6) | dst AP(6) | auth_len | ...
//
// hostapd is configured with ft_iface=vft0 (one end of a veth pair), so all of
// its RRB traffic goes through this daemon via vft1:
//   vft1 (from hostapd, upstream)  -> insert src/dst AP  -> br-lan (to UniFi)
//   br-lan (from UniFi, UniFi fmt) -> strip src/dst AP   -> vft1 (to hostapd)
// The encrypted payload is not touched: both sides use the same AES-SIV keys.
'use strict';

import * as socket from 'socket';
import { lsdir, readfile, stdout } from 'fs';

const ETH_P_OUI = 0x88b7;
const OUI = [ 0x00, 0x13, 0x74, 0x00, 0x01 ];

const HOSTAPD_IF = getenv('RRB_HOSTAPD_IF') || 'vft1';
const LAN_IF = getenv('RRB_LAN_IF') || 'br-lan';
const VERBOSE = getenv('RRB_VERBOSE') == '1';

let local = {};		// local BSSIDs ("aa:bb:..") -> interface name

// stdout is logged by procd at info level (stderr would show up as daemon.err)
function log(msg) {
	stdout.write(`rrb-unifi: ${msg}\n`);
	stdout.flush();
}

function mac_at(f, off) {
	return sprintf('%02x:%02x:%02x:%02x:%02x:%02x',
		ord(f, off), ord(f, off + 1), ord(f, off + 2),
		ord(f, off + 3), ord(f, off + 4), ord(f, off + 5));
}

function is_bcast(f, off) {
	for (let i = 0; i < 6; i++)
		if (ord(f, off + i) != 0xff)
			return false;
	return true;
}

function has_oui(f) {
	for (let i = 0; i < 5; i++)
		if (ord(f, 14 + i) != OUI[i])
			return false;
	return true;
}

// RRB body = LE16 auth_len | auth TLVs | encrypted part
function body_ok(f, off) {
	let n = length(f) - off;
	if (n < 2)
		return false;
	return 2 + (ord(f, off) | (ord(f, off + 1) << 8)) <= n;
}

function refresh_local() {
	let m = {};
	for (let ifn in (lsdir('/sys/class/net') || [])) {
		if (!match(ifn, /^phy[0-9]+-ap[0-9]+$/))
			continue;
		let addr = trim(readfile(`/sys/class/net/${ifn}/address`) || '');
		if (addr)
			m[addr] = ifn;
	}
	local = m;
}

function is_local(mac) {
	if (!local[mac])
		refresh_local();
	return !!local[mac];
}

function open_if(ifname) {
	let s = socket.create(socket.AF_PACKET, socket.SOCK_RAW, 0);
	if (!s)
		die(`socket(${ifname}): ${socket.error()}`);
	if (!s.bind({ family: socket.AF_PACKET, protocol: ETH_P_OUI,
	              interface: ifname, address: '00:00:00:00:00:00' }))
		die(`bind(${ifname}): ${socket.error()}`);
	return s;
}

function send_if(s, ifname, frame, dst) {
	if (s.send(frame, 0, { family: socket.AF_PACKET, protocol: ETH_P_OUI,
	                       interface: ifname, address: dst }) == null)
		log(`send on ${ifname} failed: ${socket.error()}`);
}

// UniFi -> hostapd: strip the 12-byte src/dst AP header, use those addresses
// as the Ethernet addresses hostapd sees.
function from_lan(f, hap) {
	if (length(f) < 34 || !has_oui(f))
		return;
	if (is_local(mac_at(f, 6)))
		return;
	if (ord(f, 20) & 1)		// multicast "src AP": not UniFi framing
		return;
	if (!body_ok(f, 32))
		return;
	let apdst = mac_at(f, 26);
	if (!is_bcast(f, 26) && !is_local(apdst))
		return;

	let out = substr(f, 26, 6) + substr(f, 20, 6) + substr(f, 12, 8) + substr(f, 32);
	if (VERBOSE)
		log(`lan->hostapd type=${ord(f, 19)} ${mac_at(f, 20)} -> ${apdst} (via ${mac_at(f, 6)})`);
	send_if(hap, HOSTAPD_IF, out, apdst);
}

// hostapd -> UniFi: insert src/dst AP after the type byte.
function from_hostapd(f, lan) {
	if (length(f) < 22 || !has_oui(f))
		return;
	let src = mac_at(f, 6), dst = mac_at(f, 0);
	if (!is_local(src))
		return;
	if (!body_ok(f, 20))
		return;

	let out = substr(f, 0, 6) + substr(f, 6, 6) + substr(f, 12, 8) +
		substr(f, 6, 6) + substr(f, 0, 6) + substr(f, 20);
	if (VERBOSE)
		log(`hostapd->lan type=${ord(f, 19)} ${src} -> ${dst}`);
	send_if(lan, LAN_IF, out, dst);
}

refresh_local();
let hap = open_if(HOSTAPD_IF);
let lan = open_if(LAN_IF);
log(`running: hostapd side ${HOSTAPD_IF}, lan side ${LAN_IF}, local BSSIDs: ${join(' ', keys(local))}`);

while (true) {
	let events = socket.poll(-1, [ hap, socket.POLLIN, 'hap' ], [ lan, socket.POLLIN, 'lan' ]);
	if (events == null)
		die(`poll: ${socket.error()}`);

	for (let ev in events) {
		if (ev[1] & (socket.POLLERR | socket.POLLHUP))
			die(`${ev[2]} socket error/hangup`);
		if (!(ev[1] & socket.POLLIN))
			continue;

		let f = ev[0].recv(2048);
		if (f == null)
			die(`recv(${ev[2]}): ${socket.error()}`);

		if (ev[2] == 'hap')
			from_hostapd(f, lan);
		else
			from_lan(f, hap);
	}
}
