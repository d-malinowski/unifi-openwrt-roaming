-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 d-malinowski
--[[
	rrb-unifi.lua -- openUF plugin: 802.11r fast roaming between an openUF AP
	and genuine UniFi APs, through the rrb-unifi translator.

	Installed by `rrb-unifi-setup install` as /etc/openuf/plugins/rrb-unifi.lua
	and enabled by its line in /etc/openuf/plugins.enabled. Needs openUF with
	the plugin hook (api 1, upstream commit 8287ecf or later); see openUF's
	docs/PLUGINS.md for the contract.

	Stock OpenWrt hostapd and UniFi's patched hostapd use the same FT key
	hierarchy and the same AES-SIV protected RRB payloads, but frame them
	differently: UniFi inserts the source and destination AP addresses (12
	bytes) after the RRB type. The translator converts between the two framings
	on a veth pair: hostapd's ft_iface is one end (vft0), the translator holds
	the other end and br-lan.

	What is left is config. For every WLAN on which openUF enables 802.11r,
	this plugin changes the four places where openUF's options differ from what
	a UniFi peer needs:

	  * mobility domain: UniFi firmware's own derivation, the first two bytes
	    of SHA1("salt" .. SSID zero-padded to 32 bytes). Verified against a
	    live U7 Lite (UniFi 8.7.11) by comparing its hostapd config's
	    mobility_domain; for example SSID "corp" -> 5de5. openUF's own hash
	    deliberately differs, so that clients never try FT towards a UniFi AP
	    without the translator.
	  * ft_psk_generate_local=0. OpenWrt defaults it to 1 for PSK and then
	    writes no key holders, so a UniFi AP pulling a PMK-R1 from this AP
	    gets no answer.
	  * nasid = this BSS's BSSID without colons, the same R0KH-ID convention
	    UniFi firmware uses ($bssid). OpenWrt sets none.
	  * wildcard key holders (r0kh ff:ff:ff:ff:ff:ff,*; r1kh 00:..:00,00:..:00),
	    keyed with the controller's iapp_key, the same two entries UniFi
	    firmware writes. hostapd learns each UniFi peer BSS from its first
	    pull or answer (after a sequence-number round trip) and then pushes
	    keys to it as well; a BSS reload forgets the learned peers. Optional
	    pre-seed: peers listed in /etc/config/rrb-unifi
	    (`list ft_peer '<bssid>,<r0kh-id>'`) get explicit entries before the
	    wildcards, so they get pushes from the first login on.

	And hostapd's ft_iface, added to hostapd_bss_options only when the
	translator's veth end exists: an ft_iface that does not exist makes
	hostapd fail the BSS, while without it the WLAN still works and only fast
	roaming to UniFi peers is lost.

	reassociation_deadline is removed, so OpenWrt's default applies (openUF
	writes UniFi's 3000 TU otherwise) and an interop AP keeps the timing the
	translator was validated with.

	If this plugin fails, openUF skips it and provisions the WLAN with its own
	values: Wi-Fi keeps working, FT to the UniFi APs does not. `rrb-unifi-setup
	verify` checks the running hostapd config for that reason.
]]

local M = {name = "rrb-unifi", api = 1}

M.RRB_CONFIG       = "rrb-unifi"
M.DEFAULT_FT_IFACE = "vft0"

-- ─── SHA1 (pure Lua, 32-bit words through ctx.util.bit) ──────────────────────

local TWO32 = 4294967296

-- Lowercase hex SHA1 of msg. Every intermediate sum is reduced mod 2^32 by
-- hand, so the result does not depend on which bit library openUF found
-- (LuaBitOp returns signed words, bit32 unsigned ones).
function M.sha1(msg, bit)
	local band, bor, bxor = bit.band, bit.bor, bit.bxor
	local lshift, rshift = bit.lshift, bit.rshift
	local function u(x) return x % TWO32 end
	local function rol(x, n) return u(bor(lshift(x, n), rshift(u(x), 32 - n))) end
	local function bnot(x) return TWO32 - 1 - u(x) end

	local len = #msg
	msg = msg .. string.char(0x80)
	msg = msg .. string.rep(string.char(0), (56 - #msg % 64) % 64)
	local bits = len * 8
	local tail = {}
	for i = 8, 1, -1 do
		tail[i] = string.char(bits % 256)
		bits = math.floor(bits / 256)
	end
	msg = msg .. table.concat(tail)

	local h0, h1, h2, h3, h4 =
		0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	local w = {}
	for chunk = 1, #msg, 64 do
		for i = 0, 15 do
			local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
			w[i] = ((a * 256 + b) * 256 + c) * 256 + d
		end
		for i = 16, 79 do
			w[i] = rol(bxor(bxor(w[i - 3], w[i - 8]), bxor(w[i - 14], w[i - 16])), 1)
		end
		local a, b, c, d, e = h0, h1, h2, h3, h4
		for i = 0, 79 do
			local f, k
			if i < 20 then
				f, k = bor(band(b, c), band(bnot(b), d)), 0x5A827999
			elseif i < 40 then
				f, k = bxor(bxor(b, c), d), 0x6ED9EBA1
			elseif i < 60 then
				f, k = bor(bor(band(b, c), band(b, d)), band(c, d)), 0x8F1BBCDC
			else
				f, k = bxor(bxor(b, c), d), 0xCA62C1D6
			end
			local t = u(rol(a, 5) + u(f) + e + k + w[i])
			e, d, c, b, a = d, c, rol(b, 30), a, t
		end
		h0, h1, h2 = u(h0 + a), u(h1 + b), u(h2 + c)
		h3, h4 = u(h3 + d), u(h4 + e)
	end
	-- %08x would raise for words >= 2^31 on OpenWrt's LNUM Lua: format each
	-- word as two 16-bit halves instead.
	local out = {}
	for _, h in ipairs({h0, h1, h2, h3, h4}) do
		out[#out + 1] = string.format("%04x%04x", math.floor(h / 65536), h % 65536)
	end
	return table.concat(out)
end

-- UniFi firmware's mobility domain for an SSID (4 hex chars).
function M.mobility_domain(ssid, bit)
	ssid = tostring(ssid or "")
	if #ssid < 32 then ssid = ssid .. string.rep(string.char(0), 32 - #ssid) end
	return M.sha1("salt" .. ssid, bit):sub(1, 4)
end

-- ─── translator config ───────────────────────────────────────────────────────

-- The optional pre-seeded UniFi peer BSSes from /etc/config/rrb-unifi, as
-- {{bssid = "aa:bb:..", r0kh_id = "aabb.."}, ...}; usually none. Malformed
-- entries are dropped with a log line rather than written into hostapd's
-- config.
function M.peers(cursor, ctx)
	local raw = cursor and cursor:get(M.RRB_CONFIG, "main", "ft_peer")
	if type(raw) == "string" then raw = {raw} end
	local out = {}
	for _, e in ipairs(type(raw) == "table" and raw or {}) do
		local bssid, r0 = tostring(e):match("^%s*([^,%s]+)%s*,%s*([^,%s]+)%s*$")
		bssid = bssid and bssid:lower()
		if ctx.util.is_mac(bssid) and r0 and r0:match("^[%w%-%._:]+$") and #r0 <= 48 then
			out[#out + 1] = {bssid = bssid, r0kh_id = r0}
		else
			ctx.log("ignoring malformed ft_peer entry " .. string.format("%q", tostring(e)))
		end
	end
	return out
end

-- The ft_iface hostapd should use, or nil when it does not exist (yet).
function M.ft_iface(cursor, ctx)
	local name = cursor and cursor:get(M.RRB_CONFIG, "main", "ft_iface")
	if type(name) ~= "string" or name == "" then name = M.DEFAULT_FT_IFACE end
	if not ctx.util.valid_ifname(name) then return nil end
	if not ctx.read_file("/sys/class/net/" .. name .. "/ifindex") then return nil end
	return name
end

-- hostapd_bss_options with our ft_iface line, keeping any other line openUF or
-- an earlier plugin put there. openUF writes none today; this keeps it safe if
-- that changes. Without the veth, our line goes and the option only when empty.
function M.bss_options(current, ifn, DELETE)
	local list = {}
	if type(current) == "table" and current ~= DELETE then
		for _, e in ipairs(current) do list[#list + 1] = e end
	elseif type(current) == "string" or type(current) == "number" then
		list[1] = current
	end
	local out = {}
	for _, e in ipairs(list) do
		if not tostring(e):match("^ft_iface=") then out[#out + 1] = e end
	end
	if ifn then out[#out + 1] = "ft_iface=" .. ifn end
	if #out == 0 then return DELETE end
	return out
end

-- ─── the hook ────────────────────────────────────────────────────────────────

-- Rewrite one WLAN's `extra` (openUF's UCI options for it) for UniFi interop.
-- Only WLANs on which openUF itself turned 802.11r on are touched: openUF
-- enables FT when either of the controller's two FT toggles asks for it, and
-- extra.ieee80211r is that decision.
function M.vap_options(extra, vap, ctx)
	if extra.ieee80211r ~= "1" then return end
	if type(ctx.util) ~= "table" or type(ctx.util.bit) ~= "table" then
		ctx.log("this openUF has no ctx.util (needs the plugin hook of 8287ecf "
			.. "or later): nothing changed")
		return
	end
	local DELETE = ctx.DELETE
	local cursor = ctx.cursor()

	extra.mobility_domain = M.mobility_domain(vap.ssid, ctx.util.bit)
	extra.ft_psk_generate_local = "0"
	extra.reassociation_deadline = DELETE

	local bssid = ctx.bssid(vap.radio, vap.ssid)
	if ctx.util.is_mac(bssid) then
		extra.nasid = (bssid:lower():gsub(":", ""))
	else
		ctx.log(string.format("%s on %s: BSSID not known yet, no nas_identifier this push",
			tostring(vap.ssid), tostring(vap.radio)))
	end

	if vap.iapp_key then
		local key = vap.iapp_key
		local r0kh, r1kh = {}, {}
		for _, p in ipairs(M.peers(cursor, ctx)) do
			r0kh[#r0kh + 1] = p.bssid .. "," .. p.r0kh_id .. "," .. key
			r1kh[#r1kh + 1] = p.bssid .. "," .. p.bssid .. "," .. key
		end
		r0kh[#r0kh + 1] = "ff:ff:ff:ff:ff:ff,*," .. key
		r1kh[#r1kh + 1] = "00:00:00:00:00:00,00:00:00:00:00:00," .. key
		extra.r0kh, extra.r1kh = r0kh, r1kh
	else
		-- Without the controller's key OpenWrt derives one from the
		-- passphrase, which no UniFi AP shares.
		ctx.log(string.format("%s: the controller sent no iapp_key, "
			.. "fast roaming to UniFi APs will not work", tostring(vap.ssid)))
	end

	local ifn = M.ft_iface(cursor, ctx)
	extra.hostapd_bss_options = M.bss_options(extra.hostapd_bss_options, ifn, DELETE)
	if not ifn then
		ctx.log("ft_iface not present, hostapd stays on the bridge: "
			.. "fast roaming to UniFi APs needs the rrb-unifi translator")
	end
end

return M
