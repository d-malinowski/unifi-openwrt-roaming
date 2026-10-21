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
// RRB_CHECK=1 prints what was derived and exits (see "rrb-unifi check").
'use strict';

import * as socket from 'socket';
import { lsdir, readfile, writefile, access, stdout } from 'fs';

const ETH_P_OUI = 0x88b7;
const OUI = [ 0x00, 0x13, 0x74, 0x00, 0x01 ];

const FT_IF = getenv('RRB_FT_IF') || 'vft0';		// hostapd's ft_iface
const PEER_IF = getenv('RRB_PEER_IF') || 'vft1';	// our end of the veth
const LAN_OVERRIDE = getenv('RRB_LAN_IF') || '';	// empty = derive
const RUN_DIR = getenv('RRB_RUN_DIR') || '/var/run';	// hostapd-*.conf
const WAIT = +(getenv('RRB_WAIT') || 120);		// s, for hostapd configs
const BSS_WAIT = 30;					// s, for BSSes to come up
const VERBOSE = getenv('RRB_VERBOSE') == '1';
const CHECK = getenv('RRB_CHECK') == '1';
const RELOAD_FLAG = '/tmp/rrb-unifi.wifi-reloaded';	// tmpfs: once per boot

let local = {};		// local BSSIDs ("aa:bb:..") -> interface name
let remote = {};	// BSSIDs of other APs we injected frames for
let unknown = {};	// LAN sources of unrecognized frames, logged once
let last_refresh = 0;

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
// interface= (first BSS of a radio) or bss= (further BSSes).
function parse_confs() {
	let list = [];
	for (let fn in sort(lsdir(RUN_DIR) || [])) {
		if (!match(fn, /^hostapd-.*\.conf$/))
			continue;
		let cur = null;
		for (let line in split(readfile(`${RUN_DIR}/${fn}`) || '', '\n')) {
			let m = match(trim(line), /^(interface|bss|bssid|bridge|ft_iface)=(.*)$/);
			if (!m)
				continue;
			if (m[1] == 'interface' || m[1] == 'bss')
				push(list, cur = { iface: m[2], file: fn, ft: [] });
			else if (!cur)
				continue;
			else if (m[1] == 'ft_iface')
				push(cur.ft, m[2]);
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
	if (length(d.bss))
		local = d.local;
	log(`local BSSIDs: ${join(' ', keys(local))}`);
}

function open_if(ifname) {
	let s = socket.create(socket.AF_PACKET, socket.SOCK_RAW, 0);
	if (!s)
		fail(`socket(${ifname}): ${socket.error()}`);
	if (!s.bind({ family: socket.AF_PACKET, protocol: ETH_P_OUI,
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
let hap = open_if(PEER_IF);
let lan = open_if(lan_if);
log(`running: hostapd side ${PEER_IF} (ft_iface ${FT_IF}), lan side ${lan_if}, ` +
    `BSSes: ${join(' ', map(d.bss, b => `${b.iface}=${b.bssid}`))}`);

while (true) {
	let events = socket.poll(-1, [ hap, socket.POLLIN, 'hap' ], [ lan, socket.POLLIN, 'lan' ]);
	if (events == null)
		fail(`poll: ${socket.error()}`);

	for (let ev in events) {
		if (ev[1] & (socket.POLLERR | socket.POLLHUP))
			fail(`${ev[2]} socket error/hangup`);
		if (!(ev[1] & socket.POLLIN))
			continue;

		let f = ev[0].recv(2048);
		if (f == null)
			fail(`recv(${ev[2]}): ${socket.error()}`);

		if (ev[2] == 'hap')
			from_hostapd(f, lan, lan_if);
		else
			from_lan(f, hap, lan_if);
	}
}
