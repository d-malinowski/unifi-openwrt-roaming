-- SPDX-License-Identifier: GPL-3.0-or-later
-- Standalone tests for openuf-plugin/rrb-unifi.lua, with a fake ctx shaped
-- like openUF's (docs/PLUGINS.md). Run: lua tests/run.lua

local P = dofile(REPO .. "/openuf-plugin/rrb-unifi.lua")
local BIT = TEST_BIT

local KEY   = "00112233445566778899aabbccddeeff"
local PEER1 = "00:00:5e:00:53:21"
local PEER2 = "00:00:5e:00:53:22"
local OWN   = "00:00:5e:00:53:2b"
local DELETE = setmetatable({}, {__tostring = function() return "<delete>" end})

local function is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end
local function valid_ifname(s)
	return type(s) == "string" and #s > 0 and #s <= 15 and s:match("^[%w%._%-]+$") ~= nil
end

-- A fake ctx: `db` is {config = {section = {option = value}}}, `present` the
-- netdevs that exist, `bssid` what ctx.bssid answers. Log lines are collected.
local function make_ctx(opts)
	opts = opts or {}
	local logged = {}
	local db = opts.db or {}
	local present = opts.present or {}
	local function read_file(path)
		local ifn = path:match("^/sys/class/net/([^/]+)/ifindex$")
		return (ifn and present[ifn]) and "9\n" or nil
	end
	local ctx = {
		DELETE = DELETE,
		bssid = function() return opts.bssid end,
		cursor = function()
			return {get = function(_, c, s, o)
				local sec = db[c] and db[c][s]
				local v = sec and sec[o]
				if v == nil then return nil, "Entry not found" end
				return v
			end}
		end,
		read_file = read_file,
		util = {bit = BIT, is_mac = is_mac, valid_ifname = valid_ifname, read_file = read_file},
		log = function(msg) logged[#logged + 1] = msg end,
	}
	if opts.no_util then ctx.util = nil end
	return ctx, logged
end

local function rrb(peers, ft_iface)
	return {["rrb-unifi"] = {main = {ft_peer = peers, ft_iface = ft_iface}}}
end

local function has_log(logged, text)
	for _, l in ipairs(logged) do
		if l:find(text, 1, true) then return true end
	end
	return false
end

-- openUF's FT options for a WLAN, as ucihelper builds them before the hook.
local function ft_extra()
	return {ieee80211r = "1", mobility_domain = "ffff", ft_over_ds = "0",
		pmk_r1_push = "1", reassociation_deadline = "3000",
		r0kh = {"ff:ff:ff:ff:ff:ff,*," .. KEY},
		r1kh = {"00:00:00:00:00:00,00:00:00:00:00:00," .. KEY}}
end

local VAP = {ssid = "corp", radio = "radio0", iapp_key = KEY}

return {
	{
		name = "plugin: the table openUF's loader expects",
		fn = function()
			assert_eq(P.name, "rrb-unifi", "name (= file name, D1)")
			assert_eq(P.api, 1, "api 1")
			assert_eq(type(P.vap_options), "function", "vap_options")
		end
	},
	{
		name = "plugin: sha1 matches the FIPS 180 test vectors",
		fn = function()
			assert_eq(P.sha1("", BIT), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "empty")
			assert_eq(P.sha1("abc", BIT), "a9993e364706816aba3e25717850c26c9cd0d89d", "abc")
			-- 56 bytes: the padding spills into a second block.
			assert_eq(P.sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BIT),
				"84983e441c3bd26ebaae4aa1f95129e5e54670f1", "two-block message")
			assert_eq(P.sha1(string.rep("a", 1000), BIT),
				"291e9a6c66994949b57ba5e650361e98fc36b1ba", "1000 x a")
		end
	},
	{
		name = "plugin: the mobility domain is UniFi firmware's",
		fn = function()
			-- Checked against a live U7 Lite's (UniFi 8.7.11) hostapd config;
			-- "corp" -> 5de5 is the same formula.
			assert_eq(P.mobility_domain("corp", BIT), "5de5", "UniFi's derivation")
			assert_eq(#P.mobility_domain(string.rep("x", 32), BIT), 4, "32 bytes: no padding")
		end
	},
	{
		name = "plugin: peers come from rrb-unifi's ft_peer list, malformed ones dropped",
		fn = function()
			local ctx, logged = make_ctx({db = rrb({
				PEER1:upper() .. ",00005e005321",
				"not-a-mac,00005e005399",
				PEER2 .. ", 00005e005322",
				PEER2 .. ",bad id;rm",
			})})
			local p = P.peers(ctx.cursor(), ctx)
			assert_eq(#p, 2, "two valid peers")
			assert_eq(p[1].bssid, PEER1, "lowercased BSSID")
			assert_eq(p[1].r0kh_id, "00005e005321", "R0KH-ID")
			assert_eq(p[2].r0kh_id, "00005e005322", "spaces around the comma are fine")
			assert_true(has_log(logged, "not-a-mac"), "a malformed entry is logged")
			-- A single entry comes back from UCI as a string, not a list.
			ctx = make_ctx({db = rrb(PEER1 .. ",00005e005321")})
			assert_eq(#P.peers(ctx.cursor(), ctx), 1, "single string entry")
			ctx = make_ctx()
			assert_eq(#P.peers(ctx.cursor(), ctx), 0, "no rrb-unifi config -> no peers")
			assert_eq(#P.peers(nil, ctx), 0, "no cursor -> no peers")
		end
	},
	{
		name = "plugin: ft_iface only when the translator's veth exists",
		fn = function()
			local ctx = make_ctx({present = {vft0 = true}})
			assert_eq(P.ft_iface(ctx.cursor(), ctx), "vft0", "default name, present")
			ctx = make_ctx({present = {vft0 = true}, db = rrb(nil, "vft7")})
			assert_nil(P.ft_iface(ctx.cursor(), ctx), "configured name, absent")
			ctx = make_ctx({present = {["x;reboot"] = true}, db = rrb(nil, "x;reboot")})
			assert_nil(P.ft_iface(ctx.cursor(), ctx), "unsafe name refused")
			ctx = make_ctx()
			assert_nil(P.ft_iface(ctx.cursor(), ctx), "no veth -> nil")
		end
	},
	{
		name = "plugin: reproduces the working U7 interop config (wildcards only)",
		fn = function()
			local ctx, logged = make_ctx({present = {vft0 = true}, bssid = OWN:upper()})
			local extra = ft_extra()
			P.vap_options(extra, VAP, ctx)
			assert_eq(extra.mobility_domain, "5de5", "UniFi mobility domain")
			assert_eq(extra.ft_psk_generate_local, "0", "key holders, not local derivation")
			assert_true(extra.reassociation_deadline == DELETE, "OpenWrt's default deadline")
			assert_eq(extra.nasid, "00005e00532b", "R0KH-ID = own BSSID")
			assert_eq(extra.pmk_r1_push, "1", "push untouched")
			assert_eq(extra.ft_over_ds, "0", "over the air untouched")
			assert_eq(#extra.r0kh, 1, "r0kh: the wildcard only")
			assert_eq(extra.r0kh[1], "ff:ff:ff:ff:ff:ff,*," .. KEY, "r0kh wildcard")
			assert_eq(#extra.r1kh, 1, "r1kh: the wildcard only")
			assert_eq(extra.r1kh[1], "00:00:00:00:00:00,00:00:00:00:00:00," .. KEY, "r1kh wildcard")
			assert_eq(type(extra.hostapd_bss_options), "table", "list option")
			assert_eq(#extra.hostapd_bss_options, 1, "one line")
			assert_eq(extra.hostapd_bss_options[1], "ft_iface=vft0", "hostapd on the veth")
			assert_eq(#logged, 0, "the normal case logs nothing")
		end
	},
	{
		name = "plugin: an optional ft_peer list pre-seeds explicit key holders",
		fn = function()
			local ctx, logged = make_ctx({present = {vft0 = true}, bssid = OWN,
				db = rrb({PEER2 .. ",00005e005322", PEER1 .. ",00005e005321"})})
			local extra = ft_extra()
			P.vap_options(extra, VAP, ctx)
			assert_eq(#extra.r0kh, 3, "two peers + wildcard")
			assert_eq(extra.r0kh[1], PEER2 .. ",00005e005322," .. KEY, "peer order kept")
			assert_eq(extra.r0kh[2], PEER1 .. ",00005e005321," .. KEY, "second peer")
			assert_eq(extra.r0kh[3], "ff:ff:ff:ff:ff:ff,*," .. KEY, "wildcard last")
			assert_eq(#extra.r1kh, 3, "r1kh: two peers + wildcard")
			assert_eq(extra.r1kh[1], PEER2 .. "," .. PEER2 .. "," .. KEY, "r1kh peer")
			assert_eq(extra.r1kh[3], "00:00:00:00:00:00,00:00:00:00:00:00," .. KEY, "r1kh wildcard")
			assert_eq(#logged, 0, "a valid list logs nothing")
		end
	},
	{
		name = "plugin: a WLAN without 802.11r is left alone",
		fn = function()
			local ctx, logged = make_ctx({present = {vft0 = true}, bssid = OWN})
			local extra = {mobility_domain = nil, ft_psk_generate_local = nil}
			P.vap_options(extra, VAP, ctx)
			assert_nil(next(extra), "nothing added")
			extra = {ieee80211r = "0"}
			P.vap_options(extra, VAP, ctx)
			assert_nil(extra.mobility_domain, "ieee80211r=0: nothing added")
			assert_eq(#logged, 0, "and nothing logged")
		end
	},
	{
		name = "plugin: FT turned on by the WPA3 toggle alone is still handled",
		fn = function()
			-- openUF sets ieee80211r when either toggle asks; the plugin keys on
			-- that, not on vap.fast_roaming_enabled.
			local ctx = make_ctx({present = {vft0 = true}, bssid = OWN})
			local extra = ft_extra()
			P.vap_options(extra, {ssid = "corp", radio = "radio0", iapp_key = KEY,
				fast_roaming_enabled = false, wpa3_fast_roaming_enabled = true}, ctx)
			assert_eq(extra.mobility_domain, "5de5", "rewritten")
		end
	},
	{
		name = "plugin: hostapd_bss_options keeps other lines, replaces our own",
		fn = function()
			assert_eq(P.bss_options(nil, nil, DELETE), DELETE, "nothing, no veth -> removed")
			local l = P.bss_options(nil, "vft0", DELETE)
			assert_eq(table.concat(l, "|"), "ft_iface=vft0", "nothing -> ours")
			l = P.bss_options({"a=1", "ft_iface=old", "b=2"}, "vft0", DELETE)
			assert_eq(table.concat(l, "|"), "a=1|b=2|ft_iface=vft0", "others kept, ours replaced")
			l = P.bss_options({"a=1", "ft_iface=vft0"}, nil, DELETE)
			assert_eq(table.concat(l, "|"), "a=1", "no veth: only our line goes")
			l = P.bss_options("a=1", "vft0", DELETE)
			assert_eq(table.concat(l, "|"), "a=1|ft_iface=vft0", "a plain string is kept")
			assert_eq(P.bss_options(DELETE, nil, DELETE), DELETE, "DELETE stays DELETE")
			l = P.bss_options(DELETE, "vft0", DELETE)
			assert_eq(table.concat(l, "|"), "ft_iface=vft0", "DELETE + veth -> ours")
		end
	},
	{
		name = "plugin: degrades without key, BSSID or veth",
		fn = function()
			local ctx, logged = make_ctx()
			local extra = {ieee80211r = "1"}
			P.vap_options(extra, {ssid = "corp", radio = "radio0"}, ctx)
			assert_eq(extra.mobility_domain, "5de5", "mobility domain still set")
			assert_nil(extra.nasid, "no BSSID -> no nasid")
			assert_nil(extra.r0kh, "no key -> openUF's key holders untouched")
			assert_true(extra.hostapd_bss_options == DELETE, "no veth -> option removed")
			assert_true(has_log(logged, "iapp_key"), "missing key logged")
			assert_true(has_log(logged, "BSSID not known"), "missing BSSID logged")
			assert_true(has_log(logged, "ft_iface not present"), "missing veth logged")
		end
	},
	{
		name = "plugin: an openUF without ctx.util gets no edit",
		fn = function()
			local ctx, logged = make_ctx({present = {vft0 = true}, bssid = OWN, no_util = true})
			local extra = ft_extra()
			P.vap_options(extra, VAP, ctx)
			assert_eq(extra.mobility_domain, "ffff", "unchanged")
			assert_nil(extra.ft_psk_generate_local, "nothing added")
			assert_true(has_log(logged, "8287ecf"), "says which openUF it needs")
		end
	},
	{
		name = "plugin: the key never reaches the log",
		fn = function()
			-- Every log path at once: no BSSID, no veth, a malformed peer.
			local ctx, logged = make_ctx({db = rrb({"bad,x", PEER1 .. ",00005e005321"})})
			P.vap_options(ft_extra(), VAP, ctx)
			assert_true(#logged >= 3, "the paths did log")
			for _, l in ipairs(logged) do
				assert_true(not l:find(KEY, 1, true), "iapp_key not logged: " .. l)
			end
		end
	},
}
