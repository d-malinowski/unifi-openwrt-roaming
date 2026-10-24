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
// its RRB traffic goes through this daemon via the other end, vft1:
//   vft1 (from hostapd, upstream)  -> insert src/dst AP  -> LAN (to UniFi)
//   LAN (from UniFi, UniFi fmt)    -> strip src/dst AP   -> vft1 (to hostapd)
// The encrypted payload is not touched: both sides use the same AES-SIV keys.
//
// Nothing about the local setup is assumed. At startup the daemon reads the
// running hostapd configs and serves the BSSes whose ft_iface is vft0:
//   - local BSSIDs: their bssid= lines
//   - LAN interface: the ft_iface OpenWRT generated for them (their network's
//     bridge, e.g. br-lan), before the ft_iface=vft0 override
// It waits (bounded) until those configs exist and the BSSes are up, then
// only blocks on its sockets.
//
// UBNT_ROAM (ethertype 0x890d, to 01:80:c2:00:00:1c): on every association a
// UniFi AP tells its peers "this client is mine now", and they drop it at once.
// Without it a UniFi AP keeps a client that roamed to OpenWRT listed for ~20 s,
// and the controller cannot pair the two halves of the roam. The daemon sends
// one for each client authorized on a served BSS, and drops a client here when
// a UniFi AP announces it. Payload (UniFi 8.7.11 hostapd, README "Roam announcements"):
//   01 f0 1a 00 | sender BSSID(6) | wlan_id(2) | AES-KW(key, 24 bytes) | 20 x 00
//   plaintext: tv_sec (LE32) | client MAC(6) | 14 x 00
// wlan_id is the mobility domain, the key is the BSS's wildcard r0kh key (both
// the UniFi controller's per-WLAN values). Needs ucode-mod-ubus/-uloop, which
// hostapd itself depends on; without them only this part is disabled.
//
// RRB_CHECK=1 prints what was derived and exits (see "rrb-unifi check").
'use strict';

import * as socket from 'socket';
import { lsdir, readfile, writefile, access, stdout } from 'fs';

const ETH_P_OUI = 0x88b7;
const OUI = [ 0x00, 0x13, 0x74, 0x00, 0x01 ];
const ETH_P_RRB = 0x890d;
const ROAM_DST = '01:80:c2:00:00:1c';
const ROAM_SKEW = 60;			// s, the UniFi receiver's limit too
const ROAM_REASON = 2;			// disassoc: previous auth no longer valid

const FT_IF = getenv('RRB_FT_IF') || 'vft0';		// hostapd's ft_iface
const PEER_IF = getenv('RRB_PEER_IF') || 'vft1';	// our end of the veth
const LAN_OVERRIDE = getenv('RRB_LAN_IF') || '';	// empty = derive
const RUN_DIR = getenv('RRB_RUN_DIR') || '/var/run';	// hostapd-*.conf
const WAIT = +(getenv('RRB_WAIT') || 120);		// s, for hostapd configs
const BSS_WAIT = 30;					// s, for BSSes to come up
const VERBOSE = getenv('RRB_VERBOSE') == '1';
const CHECK = getenv('RRB_CHECK') == '1';
const ROAM = getenv('RRB_ROAM') != '0';
const RELOAD_FLAG = '/tmp/rrb-unifi.wifi-reloaded';	// tmpfs: once per boot

let local = {};		// local BSSIDs ("aa:bb:..") -> interface name
let remote = {};	// BSSIDs of other APs we injected frames for
let unknown = {};	// LAN sources of unrecognized frames, logged once
let last_refresh = 0;
let roam_bss = {};	// served ifname -> { bssid, md, w } for UBNT_ROAM
let authz = {};		// client MAC -> { ifname, t } authorized here
let roam_noted = {};	// one-time UBNT_ROAM log lines

// stdout is logged by procd at info level (stderr would show up as daemon.err)
function log(msg) {
	stdout.write(`rrb-unifi: ${msg}\n`);
	stdout.flush();
}

function fail(msg) {
	log(`error: ${msg}`);
	exit(1);
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

function sysfs(ifn, attr) {
	return trim(readfile(`/sys/class/net/${ifn}/${attr}`) || '');
}

// All BSS blocks of all running hostapd configs. A block starts at
// interface= (first BSS of a radio) or bss= (further BSSes). Of the r0kh
// lines only the wildcard one's key is kept (UBNT_ROAM); it is never logged.
function parse_confs() {
	let list = [];
	for (let fn in sort(lsdir(RUN_DIR) || [])) {
		if (!match(fn, /^hostapd-.*\.conf$/))
			continue;
		let cur = null;
		for (let line in split(readfile(`${RUN_DIR}/${fn}`) || '', '\n')) {
			let m = match(trim(line), /^(interface|bss|bssid|bridge|ft_iface|mobility_domain|r0kh)=(.*)$/);
			if (!m)
				continue;
			if (m[1] == 'interface' || m[1] == 'bss')
				push(list, cur = { iface: m[2], file: fn, ft: [] });
			else if (!cur)
				continue;
			else if (m[1] == 'ft_iface')
				push(cur.ft, m[2]);
			else if (m[1] == 'r0kh') {
				let k = match(m[2], /^ff:ff:ff:ff:ff:ff[ ,]+\*[ ,]+([0-9a-fA-F]{32})$/);
				if (k)
					cur.key = lc(k[1]);
			}
			else
				cur[m[1]] = m[2];
		}
	}
	return list;
}

// The BSSes hostapd runs with ft_iface=FT_IF (the last ft_iface line wins),
// their BSSIDs, and the LAN interface they would have used without us.
function derive() {
	let all = parse_confs();
	let bss = filter(all, b => length(b.ft) && b.ft[length(b.ft) - 1] == FT_IF);
	let lans = {}, errors = [];

	for (let b in bss) {
		b.bssid = lc(b.bssid || sysfs(b.iface, 'address'));
		if (!match(b.bssid, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))
			push(errors, `${b.iface}: no BSSID in ${b.file} or sysfs`);
		let orig = filter(b.ft, v => v != FT_IF);
		b.lan = length(orig) ? orig[0] : b.bridge;
		if (b.lan)
			lans[b.lan] = true;
		else if (!LAN_OVERRIDE)
			push(errors, `${b.iface}: no bridge= or generated ft_iface= in ${b.file}; set lan_iface`);
	}

	let lan = LAN_OVERRIDE;
	if (!lan) {
		let l = keys(lans);
		if (length(l) == 1)
			lan = l[0];
		else if (length(l) > 1)
			push(errors, `BSSes are on different LAN interfaces (${join(', ', l)}); set lan_iface`);
	}

	let m = {};
	for (let b in bss)
		if (b.bssid)
			m[b.bssid] = b.iface;

	return { all, bss, lan, local: m, errors };
}

function hostapd_up(iface) {
	return system(`ubus list 'hostapd.${iface}' >/dev/null 2>&1`) == 0;
}

// The two ends of our veth pair must exist and be each other's peer.
function veth_errors() {
	let e = [];
	for (let ifn in [ FT_IF, PEER_IF ])
		if (!sysfs(ifn, 'ifindex'))
			push(e, `${ifn} does not exist (veth pair not configured?)`);
	if (!length(e) && sysfs(PEER_IF, 'iflink') != sysfs(FT_IF, 'ifindex'))
		push(e, `${PEER_IF} is not the veth peer of ${FT_IF}`);
	return e;
}

// ---- UBNT_ROAM ----------------------------------------------------------
// AES-128 (FIPS-197) and AES key wrap (RFC 3394). A roam costs 18 block
// operations, done on 32-bit words with T-tables: the byte-wise form took
// 54 ms per block on a 500 MHz MIPS (HH5A), so ~0.7 s per announcement.

const SBOX = [
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
const INV_SBOX = [];
for (let i = 0; i < 256; i++)
	INV_SBOX[SBOX[i]] = i;

function xt(b) {
	b <<= 1;
	return (b & 0x100) ? (b ^ 0x11b) : b;
}

// T-tables: one table lookup per byte and round does SubBytes and MixColumns
// (TE) or InvSubBytes and InvMixColumns (TD) on a 32-bit column. TEn/TDn are
// the n*8-bit right rotations of TE0/TD0. Built once, 8 KiB of entries.
const TE = [ [], [], [], [] ], TD = [ [], [], [], [] ];
for (let x = 0; x < 256; x++) {
	let s = SBOX[x], s2 = xt(s);
	let i = INV_SBOX[x], i2 = xt(i), i4 = xt(i2), i8 = xt(i4);
	let e = (s2 << 24) | (s << 16) | (s << 8) | (s2 ^ s);
	let d = ((i8 ^ i4 ^ i2) << 24) | ((i8 ^ i) << 16) | ((i8 ^ i4 ^ i) << 8) | (i8 ^ i2 ^ i);
	for (let r = 0; r < 4; r++) {
		TE[r][x] = e;
		TD[r][x] = d;
		e = ((e >> 8) | (e << 24)) & 0xffffffff;
		d = ((d >> 8) | (d << 24)) & 0xffffffff;
	}
}

// Expanded key: e = the 44 encryption round-key words, d = the decryption
// schedule of the equivalent inverse cipher (reversed, InvMixColumns applied).
function aes_key(k) {
	let w = [], rc = 1;
	for (let i = 0; i < 4; i++)
		w[i] = (k[i * 4] << 24) | (k[i * 4 + 1] << 16) | (k[i * 4 + 2] << 8) | k[i * 4 + 3];
	for (let i = 4; i < 44; i++) {
		let t = w[i - 1];
		if (i % 4 == 0) {
			t = ((SBOX[(t >> 16) & 255] << 24) | (SBOX[(t >> 8) & 255] << 16) |
			     (SBOX[t & 255] << 8) | SBOX[(t >> 24) & 255]) ^ (rc << 24);
			rc = xt(rc);
		}
		w[i] = w[i - 4] ^ t;
	}
	let d = [];
	for (let r = 0; r <= 10; r++)
		for (let j = 0; j < 4; j++) {
			let x = w[(10 - r) * 4 + j];
			if (r > 0 && r < 10)
				x = TD[0][SBOX[(x >> 24) & 255]] ^ TD[1][SBOX[(x >> 16) & 255]] ^
				    TD[2][SBOX[(x >> 8) & 255]] ^ TD[3][SBOX[x & 255]];
			d[r * 4 + j] = x;
		}
	return { e: w, d };
}

// One block as four big-endian column words; returns four words.
function aes_enc_w(k, s0, s1, s2, s3) {
	let w = k.e, T0 = TE[0], T1 = TE[1], T2 = TE[2], T3 = TE[3], S = SBOX;
	s0 ^= w[0]; s1 ^= w[1]; s2 ^= w[2]; s3 ^= w[3];
	for (let o = 4; o < 40; o += 4) {
		let t0 = T0[(s0 >> 24) & 255] ^ T1[(s1 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s3 & 255] ^ w[o];
		let t1 = T0[(s1 >> 24) & 255] ^ T1[(s2 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s0 & 255] ^ w[o + 1];
		let t2 = T0[(s2 >> 24) & 255] ^ T1[(s3 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s1 & 255] ^ w[o + 2];
		let t3 = T0[(s3 >> 24) & 255] ^ T1[(s0 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s2 & 255] ^ w[o + 3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}
	return [
		((S[(s0 >> 24) & 255] << 24) | (S[(s1 >> 16) & 255] << 16) | (S[(s2 >> 8) & 255] << 8) | S[s3 & 255]) ^ w[40],
		((S[(s1 >> 24) & 255] << 24) | (S[(s2 >> 16) & 255] << 16) | (S[(s3 >> 8) & 255] << 8) | S[s0 & 255]) ^ w[41],
		((S[(s2 >> 24) & 255] << 24) | (S[(s3 >> 16) & 255] << 16) | (S[(s0 >> 8) & 255] << 8) | S[s1 & 255]) ^ w[42],
		((S[(s3 >> 24) & 255] << 24) | (S[(s0 >> 16) & 255] << 16) | (S[(s1 >> 8) & 255] << 8) | S[s2 & 255]) ^ w[43],
	];
}

function aes_dec_w(k, s0, s1, s2, s3) {
	let w = k.d, T0 = TD[0], T1 = TD[1], T2 = TD[2], T3 = TD[3], S = INV_SBOX;
	s0 ^= w[0]; s1 ^= w[1]; s2 ^= w[2]; s3 ^= w[3];
	for (let o = 4; o < 40; o += 4) {
		let t0 = T0[(s0 >> 24) & 255] ^ T1[(s3 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s1 & 255] ^ w[o];
		let t1 = T0[(s1 >> 24) & 255] ^ T1[(s0 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s2 & 255] ^ w[o + 1];
		let t2 = T0[(s2 >> 24) & 255] ^ T1[(s1 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s3 & 255] ^ w[o + 2];
		let t3 = T0[(s3 >> 24) & 255] ^ T1[(s2 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s0 & 255] ^ w[o + 3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}
	return [
		((S[(s0 >> 24) & 255] << 24) | (S[(s3 >> 16) & 255] << 16) | (S[(s2 >> 8) & 255] << 8) | S[s1 & 255]) ^ w[40],
		((S[(s1 >> 24) & 255] << 24) | (S[(s0 >> 16) & 255] << 16) | (S[(s3 >> 8) & 255] << 8) | S[s2 & 255]) ^ w[41],
		((S[(s2 >> 24) & 255] << 24) | (S[(s1 >> 16) & 255] << 16) | (S[(s0 >> 8) & 255] << 8) | S[s3 & 255]) ^ w[42],
		((S[(s3 >> 24) & 255] << 24) | (S[(s2 >> 16) & 255] << 16) | (S[(s1 >> 8) & 255] << 8) | S[s0 & 255]) ^ w[43],
	];
}

function words(b, off, n) {
	let w = [];
	for (let i = 0; i < n; i++, off += 4)
		w[i] = (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3];
	return w;
}

function bytes(w) {
	let b = [];
	for (let x in w)
		push(b, (x >> 24) & 255, (x >> 16) & 255, (x >> 8) & 255, x & 255);
	return b;
}

// byte-array forms, for the self-test
function aes_enc(k, b) {
	return bytes(aes_enc_w(k, ...words(b, 0, 4)));
}

function aes_dec(k, b) {
	return bytes(aes_dec_w(k, ...words(b, 0, 4)));
}

// RFC 3394 with the default IV; p is a multiple of 8 bytes. The step counter
// t (at most 6n) only ever reaches the low word of A.
function kw_wrap(k, p) {
	let n = length(p) / 8, a0 = 0xa6a6a6a6, a1 = 0xa6a6a6a6, r = words(p, 0, n * 2);
	for (let j = 0, t = 1; j < 6; j++)
		for (let i = 0; i < n; i++, t++) {
			let b = aes_enc_w(k, a0, a1, r[i * 2], r[i * 2 + 1]);
			a0 = b[0];
			a1 = b[1] ^ t;
			r[i * 2] = b[2];
			r[i * 2 + 1] = b[3];
		}
	return bytes([ a0, a1, ...r ]);
}

// null when the integrity check fails (wrong key or not a key-wrap block)
function kw_unwrap(k, c) {
	let n = length(c) / 8 - 1, w = words(c, 0, n * 2 + 2), a0 = w[0], a1 = w[1], r = slice(w, 2);
	for (let j = 5, t = 6 * n; j >= 0; j--)
		for (let i = n - 1; i >= 0; i--, t--) {
			let b = aes_dec_w(k, a0, a1 ^ t, r[i * 2], r[i * 2 + 1]);
			a0 = b[0];
			a1 = b[1];
			r[i * 2] = b[2];
			r[i * 2 + 1] = b[3];
		}
	if (a0 != 0xa6a6a6a6 || a1 != 0xa6a6a6a6)
		return null;
	return bytes(r);
}

function hex_bytes(h) {
	let b = [];
	for (let i = 0; i < length(h); i += 2)
		push(b, hex(substr(h, i, 2)));
	return b;
}

function bytes_hex(b) {
	return join('', map(b, x => sprintf('%02x', x)));
}

function str_bytes(f, off, n) {
	let b = [];
	for (let i = 0; i < n; i++)
		push(b, ord(f, off + i));
	return b;
}

function mac_bytes(mac) {
	return hex_bytes(replace(mac, /:/g, ''));
}

// FIPS-197 C.1 and RFC 3394 4.1. A wrong result disables UBNT_ROAM only.
function aes_selftest() {
	let w = aes_key(hex_bytes('000102030405060708090a0b0c0d0e0f'));
	let pt = hex_bytes('00112233445566778899aabbccddeeff');
	let ct = aes_enc(w, pt);
	let kw = kw_wrap(w, pt);
	return bytes_hex(ct) == '69c4e0d86a7b0430d8cdb78070b4c55a' &&
		bytes_hex(aes_dec(w, ct)) == bytes_hex(pt) &&
		bytes_hex(kw) == '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5' &&
		bytes_hex(kw_unwrap(w, kw) || []) == bytes_hex(pt) &&
		kw_unwrap(w, [ ...slice(kw, 0, 23), kw[23] ^ 1 ]) == null;
}

// served BSSes that can take part: FT with a mobility domain and a wildcard key
function roam_config(bss) {
	let m = {};
	for (let b in bss)
		if (b.bssid && b.key && match(b.mobility_domain || '', /^[0-9a-fA-F]{4}$/))
			m[b.iface] = { bssid: b.bssid, md: lc(b.mobility_domain), w: aes_key(hex_bytes(b.key)) };
	return m;
}

function roam_note(key, msg) {
	if (roam_noted[key])
		return;
	roam_noted[key] = true;
	log(msg);
}

// 64-byte payload as UniFi sends it, for client sta on ifname
function roam_payload(rb, sta, now) {
	let p = [ now & 0xff, (now >> 8) & 0xff, (now >> 16) & 0xff, (now >> 24) & 0xff, ...mac_bytes(sta) ];
	while (length(p) < 24)
		push(p, 0);
	let out = [ 0x01, 0xf0, 0x1a, 0x00, ...mac_bytes(rb.bssid), ...hex_bytes(rb.md), ...kw_wrap(rb.w, p) ];
	while (length(out) < 64)
		push(out, 0);
	return out;
}

// Decode a received payload (frame offset 14). Returns { bssid, md, sta, ts }
// or a string saying why it was dropped; null for frames that are not UBNT_ROAM.
function roam_parse(f) {
	if (length(f) < 14 + 44 || ord(f, 14) != 0x01 || ord(f, 15) != 0xf0)
		return null;
	let bssid = mac_at(f, 18), md = sprintf('%02x%02x', ord(f, 24), ord(f, 25));
	if (local[bssid])
		return 'own';		// our own frame, seen on the way out
	let rb = null;
	for (let ifn, b in roam_bss)
		if (b.md == md) {
			rb = b;
			break;
		}
	if (!rb)
		return 'other WLAN';
	let p = kw_unwrap(rb.w, str_bytes(f, 26, 32));
	if (!p)
		return { bssid, md, error: 'key' };
	let ts = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
	return { bssid, md, ts, sta: sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...slice(p, 4, 10)) };
}

let ubus_conn = null;

function roam_send(rs, lan_if, lan_mac, ifname, sta) {
	let rb = roam_bss[ifname];
	if (!rb)
		return;
	let pl = roam_payload(rb, sta, time());
	let frame = chr(...mac_bytes(ROAM_DST), ...mac_bytes(lan_mac), 0x89, 0x0d, ...pl);
	if (rs.send(frame, 0, { family: socket.AF_PACKET, protocol: ETH_P_RRB,
	                        interface: lan_if, address: ROAM_DST }) == null)
		log(`UBNT_ROAM send on ${lan_if} failed: ${socket.error()}`);
	else if (VERBOSE)
		log(`UBNT_ROAM sent: ${sta} on ${ifname} (${rb.bssid})`);
}

function roam_rx(f) {
	let r = roam_parse(f);
	if (r == null || type(r) == 'string')
		return;
	if (r.error) {
		roam_note(`key ${r.bssid}`, `UBNT_ROAM from ${r.bssid} (wlan_id ${r.md}) does not decrypt with this BSS's r0kh key; is it the UniFi WLAN's key?`);
		return;
	}
	roam_note(`ok ${r.bssid}`, `UBNT_ROAM from ${r.bssid} (wlan_id ${r.md}): key verified`);
	let now = time();
	if (r.ts > now + ROAM_SKEW || r.ts < now - ROAM_SKEW) {
		roam_note(`skew ${r.bssid}`, `UBNT_ROAM from ${r.bssid} ignored: clock differs by ${now - r.ts} s (NTP?)`);
		return;
	}
	let a = authz[r.sta];
	if (a && a.t >= r.ts) {
		if (VERBOSE)
			log(`UBNT_ROAM: ${r.sta} came back here after the announcement; kept`);
		return;
	}
	for (let ifn, b in roam_bss) {
		if (b.md != r.md)
			continue;
		let cl = ubus_conn.call(`hostapd.${ifn}`, 'get_clients', {});
		if (!cl || !cl.clients || !cl.clients[r.sta])
			continue;
		ubus_conn.call(`hostapd.${ifn}`, 'del_client', { addr: r.sta, reason: ROAM_REASON, deauth: false });
		log(`UBNT_ROAM: ${r.sta} roamed to ${r.bssid}; disassociated from ${ifn}`);
	}
	delete authz[r.sta];
}

// hostapd notifications. Always answer {} (status OK): with notify_response
// on, any other answer would make hostapd reject auth/assoc/probe requests.
function roam_notify(req, rs, lan_if, lan_mac) {
	let d = req.data || {};
	if (req.type == 'sta-authorized' && d.address && roam_bss[d.ifname]) {
		let sta = lc(d.address);
		if (length(authz) > 512)
			authz = {};
		authz[sta] = { ifname: d.ifname, t: time() };
		roam_send(rs, lan_if, lan_mac, d.ifname, sta);
	} else if (req.type == 'disassoc' && d.address) {
		let a = authz[lc(d.address)];
		if (a && a.ifname == d.ifname)
			delete authz[lc(d.address)];
	}
	return {};
}

// ubus + uloop, or null (UBNT_ROAM off, translation still runs)
function roam_modules() {
	try {
		return { ubus: require('ubus'), uloop: require('uloop') };
	} catch (e) {
		return null;
	}
}

function check() {
	let d = derive();
	let errors = veth_errors();
	for (let e in d.errors)
		push(errors, e);

	print(`hostapd configs in ${RUN_DIR}:\n`);
	if (!length(d.all))
		print('  none (Wi-Fi not running?)\n');
	for (let b in d.all) {
		let ours = index(d.bss, b) >= 0;
		print(sprintf('  %-12s %-20s ft_iface=%s %s\n', b.iface, b.file,
			join(',', b.ft) || '-',
			ours ? `-> served, BSSID ${b.bssid}, hostapd ${hostapd_up(b.iface) ? 'up' : 'DOWN'}` : '(not using ' + FT_IF + ')'));
	}
	if (!length(d.bss))
		push(errors, `no hostapd BSS uses ft_iface=${FT_IF} (set hostapd_bss_options 'ft_iface=${FT_IF}')`);
	for (let b in d.bss)
		if (!hostapd_up(b.iface))
			push(errors, `hostapd is not running ${b.iface} (see logread -e hostapd)`);
	print(`veth: ${FT_IF} (hostapd) <-> ${PEER_IF} (rrb-unifi)\n`);
	print(`LAN interface: ${d.lan || '?'}${LAN_OVERRIDE ? ' (set in config)' : ' (derived)'}`);
	print(d.lan && !sysfs(d.lan, 'ifindex') ? ' DOES NOT EXIST\n' : '\n');
	if (d.lan && !sysfs(d.lan, 'ifindex'))
		push(errors, `LAN interface ${d.lan} does not exist`);

	let rb = roam_config(d.bss);
	if (!ROAM)
		print('UBNT_ROAM: off (roam_announce 0)\n');
	else if (!roam_modules())
		print('UBNT_ROAM: unavailable (ucode-mod-ubus or ucode-mod-uloop missing)\n');
	else if (!aes_selftest())
		push(errors, 'UBNT_ROAM: AES self-test failed');
	else if (!length(rb))
		print('UBNT_ROAM: off (no served BSS has a mobility_domain and a wildcard r0kh key)\n');
	else
		print(`UBNT_ROAM: on for ${join(' ', map(sort(keys(rb)), i => `${i} (wlan_id ${rb[i].md})`))}\n`);

	for (let e in errors)
		print(`ERROR: ${e}\n`);
	print(length(errors) ? 'check FAILED\n' : 'check OK\n');
	exit(length(errors) ? 1 : 0);
}

// Wait until hostapd configs with ft_iface=FT_IF exist and their BSSes are
// up. If a BSS stays down (hostapd could not open ft_iface because the veth
// did not exist yet when Wi-Fi started), run "wifi up" once per boot.
// ("wifi reload" does not restart a BSS that failed: it only reloads settings.)
function startup() {
	let start = time(), found = 0;

	while (true) {
		let d = derive();
		let now = time();

		if (length(d.bss)) {
			if (!found)
				found = now;
			let down = map(filter(d.bss, b => !hostapd_up(b.iface)), b => b.iface);
			if (!length(down))
				return d;
			if (now - found >= BSS_WAIT) {
				if (access(RELOAD_FLAG)) {
					// already reloaded this boot; run with what is up
					log(`warning: hostapd BSS still down: ${join(' ', down)}`);
					return d;
				}
				writefile(RELOAD_FLAG, `${now}\n`);
				log(`hostapd BSS down: ${join(' ', down)}; running wifi up (once per boot)`);
				system('wifi up');
				found = 0;
				start = now;
			}
		} else if (now - start >= WAIT) {
			fail(`no hostapd BSS uses ft_iface=${FT_IF} after ${WAIT}s (set hostapd_bss_options 'ft_iface=${FT_IF}' on the wifi-iface)`);
		}
		sleep(2000);
	}
}

// Re-read the hostapd configs when hostapd sends from an unknown BSSID (Wi-Fi
// config changed). Event driven and rate limited, not polled.
function refresh_local() {
	if (time() - last_refresh < 10)
		return;
	last_refresh = time();
	let d = derive();
	if (length(d.bss)) {
		local = d.local;
		if (ubus_conn)
			roam_bss = roam_config(d.bss);
	}
	log(`local BSSIDs: ${join(' ', keys(local))}`);
}

function open_if(ifname, proto) {
	let s = socket.create(socket.AF_PACKET, socket.SOCK_RAW, 0);
	if (!s)
		fail(`socket(${ifname}): ${socket.error()}`);
	if (!s.bind({ family: socket.AF_PACKET, protocol: proto,
	              interface: ifname, address: '00:00:00:00:00:00' }))
		fail(`bind(${ifname}): ${socket.error()}`);
	return s;
}

function send_if(s, ifname, frame, dst) {
	if (s.send(frame, 0, { family: socket.AF_PACKET, protocol: ETH_P_OUI,
	                       interface: ifname, address: dst }) == null)
		log(`send on ${ifname} failed: ${socket.error()}`);
}

// Log each LAN source of frames we cannot translate once, so a format
// change (e.g. after a UniFi firmware update) is visible.
function note_unknown(f, src) {
	if (unknown[src] || length(keys(unknown)) >= 64)
		return;
	unknown[src] = true;
	if (body_ok(f, 20))
		log(`ignoring upstream-format RRB frames from ${src} (an AP without rrb-unifi?)`);
	else
		log(`ignoring unrecognized RRB frames from ${src} (len ${length(f)}, type ${ord(f, 19)}); UniFi format changed?`);
}

// UniFi -> hostapd: strip the 12-byte src/dst AP header, use those addresses
// as the Ethernet addresses hostapd sees.
function from_lan(f, hap, lan_if) {
	if (length(f) < 22 || !has_oui(f))
		return;
	let src = mac_at(f, 6);
	if (local[src])			// our own frame (packet sockets see outgoing too)
		return;
	if (length(f) < 34 || (ord(f, 20) & 1) || !body_ok(f, 32)) {
		note_unknown(f, src);
		return;
	}
	let apdst = mac_at(f, 26);
	if (!is_bcast(f, 26) && !local[apdst])
		return;			// for another AP

	let apsrc = mac_at(f, 20);
	remote[apsrc] = true;
	let out = substr(f, 26, 6) + substr(f, 20, 6) + substr(f, 12, 8) + substr(f, 32);
	if (VERBOSE)
		log(`${lan_if}->hostapd type=${ord(f, 19)} ${apsrc} -> ${apdst} (via ${src})`);
	send_if(hap, PEER_IF, out, apdst);
}

// hostapd -> UniFi: insert src/dst AP after the type byte.
function from_hostapd(f, lan, lan_if) {
	if (length(f) < 22 || !has_oui(f))
		return;
	let src = mac_at(f, 6), dst = mac_at(f, 0);
	if (remote[src])		// our own injected frame
		return;
	if (!local[src])
		refresh_local();
	if (!local[src] || !body_ok(f, 20))
		return;

	let out = substr(f, 0, 6) + substr(f, 6, 6) + substr(f, 12, 8) +
		substr(f, 6, 6) + substr(f, 0, 6) + substr(f, 20);
	if (VERBOSE)
		log(`hostapd->${lan_if} type=${ord(f, 19)} ${src} -> ${dst}`);
	send_if(lan, lan_if, out, dst);
}

if (CHECK)
	check();

for (let e in veth_errors())
	fail(e);

let d = startup();
for (let e in d.errors)
	fail(e);
if (!sysfs(d.lan, 'ifindex'))
	fail(`LAN interface ${d.lan} does not exist`);

local = d.local;
let lan_if = d.lan;
let hap = open_if(PEER_IF, ETH_P_OUI);
let lan = open_if(lan_if, ETH_P_OUI);
log(`running: hostapd side ${PEER_IF} (ft_iface ${FT_IF}), lan side ${lan_if}, ` +
    `BSSes: ${join(' ', map(d.bss, b => `${b.iface}=${b.bssid}`))}`);

function on_frame(s, name) {
	let f = s.recv(2048);
	if (f == null)
		fail(`recv(${name}): ${socket.error()}`);
	if (name == 'hap')
		from_hostapd(f, lan, lan_if);
	else if (name == 'lan')
		from_lan(f, hap, lan_if);
	else
		roam_rx(f);
}

// Without UBNT_ROAM: the 1.2 loop, unchanged.
function poll_loop() {
	while (true) {
		let events = socket.poll(-1, [ hap, socket.POLLIN, 'hap' ], [ lan, socket.POLLIN, 'lan' ]);
		if (events == null)
			fail(`poll: ${socket.error()}`);

		for (let ev in events) {
			if (ev[1] & (socket.POLLERR | socket.POLLHUP))
				fail(`${ev[2]} socket error/hangup`);
			if (ev[1] & socket.POLLIN)
				on_frame(ev[0], ev[2]);
		}
	}
}

let mods = ROAM ? roam_modules() : null;
let why = !ROAM ? 'off (roam_announce 0)' :
	!mods ? 'ucode-mod-ubus or ucode-mod-uloop missing' :
	!aes_selftest() ? 'AES self-test FAILED' : null;
if (!why) {
	roam_bss = roam_config(d.bss);
	if (!length(roam_bss))
		why = 'no served BSS has a mobility_domain and a wildcard r0kh key';
}
if (!why) {
	mods.uloop.init();
	ubus_conn = mods.ubus.connect();
	if (!ubus_conn)
		why = `ubus: ${mods.ubus.error()}`;
}
if (why) {
	log(`UBNT_ROAM disabled: ${why}`);
	poll_loop();
}

let uloop = mods.uloop;
let rs = open_if(lan_if, ETH_P_RRB);

// An exception in a uloop callback would end uloop.run(): log it instead.
function guarded(what, fn) {
	return (...args) => {
		try {
			return fn(...args);
		} catch (e) {
			log(`error in ${what}: ${e.message}`);
			return what == 'notify' ? {} : null;
		}
	};
}
let lan_mac = sysfs(lan_if, 'address');
let refresh_timer = null;

// "hostapd.*" also covers BSS objects created later (wifi reload). When one
// goes away, re-read the configs a little later: BSSIDs or keys may change.
let sub = ubus_conn.subscriber(
	guarded('notify', req => roam_notify(req, rs, lan_if, lan_mac)),
	id => {
		if (!refresh_timer)
			refresh_timer = uloop.timer(5000, () => {
				refresh_timer = null;
				last_refresh = 0;
				refresh_local();
			});
	},
	[ 'hostapd.*' ]);
if (!sub)
	fail(`ubus subscriber: ${mods.ubus.error()}`);

let handles = map([ [ hap, 'hap' ], [ lan, 'lan' ], [ rs, 'roam' ] ],
	h => uloop.handle(h[0], guarded(h[1], ev => on_frame(h[0], h[1])), uloop.ULOOP_READ));
log(`UBNT_ROAM on: ${join(' ', map(sort(keys(roam_bss)), i => `${i} (wlan_id ${roam_bss[i].md})`))}, ` +
    `sent from ${lan_mac} on ${lan_if}`);
uloop.run();
// uloop ends on SIGTERM/SIGINT (stop, restart) or after an unhandled ubus error
log('stopped');
exit(0);
