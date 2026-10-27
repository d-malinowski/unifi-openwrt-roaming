-- SPDX-License-Identifier: GPL-3.0-or-later
-- Contract tests: the plugin loaded by openUF's own plugins.lua and run through
-- ucihelper.apply_config, with a recording UCI cursor (as openUF's
-- tests/test_plugins.lua does). Run from an openUF checkout (8287ecf or later):
--   cd /path/to/openUF && lua /path/to/rrb-unifi/tests/run.lua --openuf

local plugins   = dofile("openuf/plugins.lua")
local ucihelper = dofile("openuf/ucihelper.lua")

local f = assert(io.open(REPO .. "/openuf-plugin/rrb-unifi.lua", "r"))
local SRC = f:read("*a")
f:close()

local KEY   = "00112233445566778899aabbccddeeff"
local PEER1 = "00:00:5e:00:53:21"
local OWN   = "00:00:5e:00:53:2b"
local PLUGIN_PATH = plugins.DIR .. "/rrb-unifi.lua"

-- Run fn(logged) with plugins.lua reading our plugin, `enabled` as the
-- plugins.enabled file and the veth present when `veth` is true.
local function with_plugin(enabled, veth, fn)
	local orig_read, orig_log = plugins._read_file, plugins._log
	local logged = {}
	plugins._read_file = function(path)
		if path == PLUGIN_PATH then return SRC end
		if path == plugins.LIST then return enabled end
		if veth and path == "/sys/class/net/vft0/ifindex" then return "9\n" end
		return nil
	end
	plugins._log = function(msg) logged[#logged + 1] = msg end
	plugins._reset()
	local ok, err = pcall(fn, logged)
	plugins._read_file, plugins._log = orig_read, orig_log
	plugins._reset()
	if not ok then error(err, 0) end
end

local function has_log(logged, text)
	for _, l in ipairs(logged) do
		if l:find(text, 1, true) then return true end
	end
	return false
end

-- One apply_config run over `vaps` with an in-memory cursor that also holds
-- /etc/config/rrb-unifi, with the optional ft_peer list `peers`. Returns the
-- wireless sections.
local function run(vaps, cfg, peers)
	local db = {["rrb-unifi"] = {main = {[".name"] = "main", [".type"] = "rrb",
		ft_peer = peers}}}
	local order = {}
	local c = {}
	function c:set(config, section, a, b)
		assert(tostring(section):match("^[%w_]+$"), "invalid section " .. tostring(section))
		db[config] = db[config] or {}
		if not db[config][section] then
			db[config][section] = {[".name"] = section}
			order[config] = order[config] or {}
			order[config][#order[config] + 1] = section
		end
		if b == nil then db[config][section][".type"] = a
		elseif type(b) == "table" then
			local l = {}
			for i, v in ipairs(b) do l[i] = tostring(v) end
			db[config][section][a] = l
		else db[config][section][a] = b end
	end
	function c:foreach(config, stype, fn)
		for _, n in ipairs(order[config] or {}) do
			local s = db[config][n]
			if s and s[".type"] == stype then fn(s) end
		end
	end
	function c:delete(config, section, option)
		if option ~= nil then
			if db[config] and db[config][section] then db[config][section][option] = nil end
			return
		end
		if db[config] then db[config][section] = nil end
		for i, n in ipairs(order[config] or {}) do
			if n == section then table.remove(order[config], i); break end
		end
	end
	function c:get(config, section, option)
		local s = db[config] and db[config][section]
		local v = s and s[option]
		if v == nil then return nil, "Entry not found" end
		return v
	end
	function c:commit() end

	local orig = {ucihelper._uci, ucihelper._popen, ucihelper._read_file, ucihelper._run_cmd,
		ucihelper._plugins, ucihelper._bcfilter, ucihelper.get_ifname_for_vap}
	ucihelper._uci = {cursor = function() return c end}
	ucihelper._popen = function() return "" end
	ucihelper._read_file = function(path)
		if path == "/sys/class/net/phy0-ap0/address" then return OWN .. "\n" end
		return nil
	end
	ucihelper._run_cmd = function() return true end
	ucihelper._plugins = plugins
	ucihelper._bcfilter = {reconcile = function() end}
	ucihelper.get_ifname_for_vap = function(radio, ssid)
		return (radio == "radio0" and ssid == "corp") and "phy0-ap0" or nil
	end
	c:set("wireless", "radio0", "wifi-device")
	local real = io.stderr
	io.stderr = {write = function() end}
	local ok, err = pcall(ucihelper.apply_config, {radio_table = {}, vap_table = vaps}, cfg)
	io.stderr = real
	ucihelper._uci, ucihelper._popen, ucihelper._read_file, ucihelper._run_cmd,
		ucihelper._plugins, ucihelper._bcfilter, ucihelper.get_ifname_for_vap =
		orig[1], orig[2], orig[3], orig[4], orig[5], orig[6], orig[7]
	if not ok then error(err, 0) end
	return db.wireless
end

local FT_VAP = {ssid = "corp", radio = "radio0", security = "wpa2",
	x_passphrase = "hunter22", fast_roaming_enabled = true, iapp_key = KEY}
local PLAIN_VAP = {ssid = "guest", radio = "radio0", security = "wpa2",
	x_passphrase = "hunter22", iapp_key = KEY}

return {
	{
		name = "contract: openUF's loader accepts the plugin from plugins.enabled",
		fn = function()
			assert_eq(plugins.API, 1, "this openUF speaks api 1")
			with_plugin("# rrb-unifi-setup\nrrb-unifi\n", true, function(logged)
				local list = plugins.enabled({config = {}})
				assert_eq(#list, 1, "loaded")
				assert_eq(list[1].name, "rrb-unifi", "by its name")
				assert_eq(#logged, 0, "no load error: " .. tostring(logged[1]))
				assert_true(plugins.fingerprint({config = {}}):find("^rrb%-unifi:%d+$") ~= nil,
					"in the fingerprint, so enabling it makes the controller push again")
			end)
		end
	},
	{
		name = "contract: apply_config writes the interop options, none refused",
		fn = function()
			with_plugin("rrb-unifi\n", true, function(logged)
				local w = run({FT_VAP}, {config = {}})
				local s = w.openuf_radio0_corp
				assert_eq(#logged, 0, "not skipped: " .. tostring(logged[1]))
				assert_eq(s.ieee80211r, "1", "FT on")
				assert_eq(s.mobility_domain, "5de5", "UniFi mobility domain")
				assert_eq(s.ft_psk_generate_local, "0", "key holders")
				assert_eq(s.nasid, "00005e00532b", "nasid from ctx.bssid")
				assert_nil(s.reassociation_deadline, "DELETE removed openUF's 3000")
				assert_eq(s.pmk_r1_push, "1", "openUF's push kept")
				assert_eq(#s.r0kh, 1, "r0kh wildcard only")
				assert_eq(s.r0kh[1], "ff:ff:ff:ff:ff:ff,*," .. KEY, "r0kh wildcard")
				assert_eq(#s.r1kh, 1, "r1kh wildcard only")
				assert_eq(s.r1kh[1], "00:00:00:00:00:00,00:00:00:00:00:00," .. KEY, "r1kh wildcard")
				assert_eq(#s.hostapd_bss_options, 1, "one line")
				assert_eq(s.hostapd_bss_options[1], "ft_iface=vft0", "veth via ctx.read_file")
				assert_eq(s.ssid, "corp", "identity untouched")

				s = run({FT_VAP}, {config = {}}, {PEER1 .. ",00005e005321"}).openuf_radio0_corp
				assert_eq(#logged, 0, "pre-seed: not skipped: " .. tostring(logged[1]))
				assert_eq(#s.r0kh, 2, "pre-seed: peer + wildcard")
				assert_eq(s.r0kh[1], PEER1 .. ",00005e005321," .. KEY, "peer from ctx.cursor()")
				assert_eq(s.r1kh[2], "00:00:00:00:00:00,00:00:00:00:00:00," .. KEY, "r1kh wildcard last")
			end)
		end
	},
	{
		name = "contract: a WLAN without FT is pushed exactly as without the plugin",
		fn = function()
			local base = run({PLAIN_VAP}, {config = {}}).openuf_radio0_guest
			with_plugin("rrb-unifi\n", true, function(logged)
				local s = run({PLAIN_VAP}, {config = {}}).openuf_radio0_guest
				for k, v in pairs(base) do
					if type(v) == "table" then
						assert_eq(table.concat(s[k], ","), table.concat(v, ","), k)
					else
						assert_eq(s[k], v, k)
					end
				end
				for k in pairs(s) do assert_true(base[k] ~= nil, "no extra option " .. k) end
				assert_eq(#logged, 0, "nothing logged")
			end)
		end
	},
	{
		name = "contract: without the veth the WLAN is still pushed, without ft_iface",
		fn = function()
			with_plugin("rrb-unifi\n", false, function(logged)
				local s = run({FT_VAP}, {config = {}}).openuf_radio0_corp
				assert_eq(s.mobility_domain, "5de5", "interop options still set")
				assert_nil(s.hostapd_bss_options, "no ft_iface")
				assert_true(has_log(logged, "plugin rrb-unifi: ft_iface not present")
					or has_log(logged, "rrb-unifi: ft_iface not present"), "logged with the plugin name")
				assert_true(not has_log(logged, "skipped"), "not skipped")
			end)
		end
	},
	{
		name = "contract: removing the line gives openUF's own values on the next push",
		fn = function()
			with_plugin("# removed\n", true, function()
				local s = run({FT_VAP}, {config = {}}).openuf_radio0_corp
				assert_eq(s.mobility_domain, ucihelper.derive_mobility_domain("corp"), "openUF's domain")
				assert_eq(s.reassociation_deadline, "3000", "openUF's deadline")
				assert_nil(s.ft_psk_generate_local, "left to OpenWrt")
				assert_nil(s.nasid, "no nasid")
				assert_nil(s.hostapd_bss_options, "no ft_iface")
			end)
		end
	},
}
