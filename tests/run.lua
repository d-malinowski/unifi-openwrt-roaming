-- SPDX-License-Identifier: GPL-3.0-or-later
-- Tests for the openUF plugin (openuf-plugin/rrb-unifi.lua). Lua 5.1, needs a
-- bit library (LuaBitOp `bit`, as OpenWrt ships, or `bit32`).
--
--   lua tests/run.lua                      standalone tests (from the repo root)
--   cd /path/to/openUF && lua /path/to/rrb-unifi/tests/run.lua --openuf
--                                          also the contract tests, through
--                                          openUF's own plugins.lua and
--                                          ucihelper.apply_config (needs
--                                          openUF 8287ecf or later and lua-cjson)
--
-- Exit code 0 = all pass, 1 = any failure.

local repo = (arg and arg[0] or "tests/run.lua"):match("^(.-)/?tests/run%.lua$")
REPO = (repo == nil or repo == "") and "." or repo
local with_openuf = arg and arg[1] == "--openuf"

local ok_bit, BIT = pcall(require, "bit")
if not ok_bit then ok_bit, BIT = pcall(require, "bit32") end
if not ok_bit then
	print("FATAL: no bit library (install lua-bitop)")
	os.exit(1)
end
TEST_BIT = BIT

function assert_eq(got, expected, label)
	if got ~= expected then
		error(string.format("%s\n  expected: %s\n  got:      %s",
			label or "(no label)", tostring(expected), tostring(got)), 2)
	end
end

function assert_neq(got, other, label)
	if got == other then
		error(string.format("%s: expected a different value, both are %s",
			label or "(no label)", tostring(got)), 2)
	end
end

function assert_true(v, label)
	if not v then error(string.format("%s: expected true, got %s", label or "(no label)", tostring(v)), 2) end
end

function assert_nil(v, label)
	if v ~= nil then error(string.format("%s: expected nil, got %s", label or "(no label)", tostring(v)), 2) end
end

local files = {"tests/test_plugin.lua"}
if with_openuf then
	local f = io.open("openuf/plugins.lua", "r")
	if not f then
		print("FATAL: --openuf needs the current directory to be an openUF checkout "
			.. "with openuf/plugins.lua (8287ecf or later)")
		os.exit(1)
	end
	f:close()
	files[#files + 1] = "tests/test_openuf_contract.lua"
end

local passed, failed = 0, 0
for _, file in ipairs(files) do
	local chunk, err = loadfile(REPO .. "/" .. file)
	local ok, tests = false, err
	if chunk then ok, tests = pcall(chunk) end
	if not ok then
		print("ERROR loading " .. file .. ": " .. tostring(tests))
		failed = failed + 1
	else
		for _, t in ipairs(tests) do
			local tok, terr = pcall(t.fn)
			if tok then
				passed = passed + 1
				print("PASS  " .. t.name)
			else
				failed = failed + 1
				print("FAIL  " .. t.name .. "\n      " .. tostring(terr):gsub("\n", "\n      "))
			end
		end
	end
end
print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
