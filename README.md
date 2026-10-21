# unifi-openwrt-roaming

**Extend your UniFi Wi-Fi with any OpenWrt device, including old routers you
already own, and get real fast roaming between them in both directions.**

UniFi and OpenWrt both support 802.11r fast roaming. Until now they couldn't
pass roaming keys to each other, because UniFi uses a slightly modified
message format. In practice, phones often got stuck on the OpenWrt AP or
dropped the connection. This project translates between the two formats on the
OpenWrt side. Nothing on the UniFi AP is changed. Phones then roam between
UniFi and OpenWrt APs as smoothly as between two UniFi APs, without dropping
Wi-Fi calls or video calls. A spare router running OpenWrt becomes a real
part of your UniFi network for roaming. It won't appear in the UniFi
controller, though: you still manage it through OpenWrt.

Use this if you added an OpenWrt AP to a UniFi network, enabled fast roaming
on both, copied the mobility domain, and roaming *mostly* works, but sometimes
the phone gets stuck on the OpenWrt AP, disconnects, or drops to mobile data
instead of moving to the UniFi AP.

The translator, `rrb-unifi`, is a small ucode script (under 400 lines,
including comments and self-checks) that runs on the OpenWrt AP. It is named
after RRB, the messages hostapd uses to exchange roaming keys between APs. It
translates those messages between the two vendors. It needs no compiling and
no Python, so it fits even on old devices. It adds two small packages that are
already in the OpenWrt feeds. A setup tool, `rrb-unifi-setup`, installs it,
reads the settings from the UniFi AP and configures OpenWrt to match.


## The problem

To roam fast, the new AP needs a key (PMK-R1) that comes from the AP where the
client did its first, full login. The AP holding that key is the "R0KH".
Typical mixed setups use `ft_psk_generate_local=1` on OpenWrt. That
setting lets an AP compute the key from the Wi-Fi password, so no key exchange
is needed. UniFi APs don't do that: they always fetch the key from the R0KH
over the LAN.

The result:

- The client first connects to UniFi: roaming works in both directions.
  OpenWrt computes the key locally, and UniFi is the R0KH, so it has the key.
- The client first connects to OpenWrt (Wi-Fi toggled, coming home, after a
  dropout): every roam to UniFi fails until the client happens to do a full
  login on UniFi again. The UniFi AP asks OpenWrt for the key, and OpenWrt
  can't answer.

You can't fix this with configuration alone. With `ft_psk_generate_local=0`
and the UniFi key in `r0kh`/`r1kh`, OpenWrt does exchange messages with the
UniFi AP. But both sides drop each other's messages. The UniFi AP logs:

```
FT: RRB-OUI frame too short
```


## Root cause

Both APs run hostapd and use the same RRB-OUI messages (ethertype 0x88b7) with
the same encryption. UniFi's hostapd inserts 12 extra bytes, the source and
destination AP address, after the message type:

```
OpenWrt (upstream hostapd):  00 13 74 00 01 | type | auth_len | auth TLVs | encrypted
UniFi:                       00 13 74 00 01 | type | src AP (6) | dst AP (6) | auth_len | auth TLVs | encrypted
```

UniFi sends these messages from the AP's Ethernet MAC address instead of the
BSSID, so it carries the BSSIDs inside the payload. Everything else is
identical. That includes the AES-SIV encryption and the key derivation: a
128-bit key is expanded with `HMAC-SHA256(key, "FT OLDKEY")`, the same as
upstream hostapd's `rkh_derive_key()`. This was checked by decrypting captured
frames from both vendors with the same key.

So adding or stripping those 12 bytes is enough to make them talk.

You can check this on your own network with `tools/rrb-decrypt.py`. It
decrypts captured RRB-OUI frames with your r0kh/r1kh key and shows which
format each AP uses:

```sh
# on OpenWrt (needs tcpdump or tcpdump-mini); roam a client a few times meanwhile
# br-lan = the bridge of your Wi-Fi network ("rrb-unifi check" shows it)
tcpdump -i br-lan -e -n -w /tmp/rrb.pcap 'ether proto 0x88b7'

# on a PC (pip install cryptography)
python3 tools/rrb-decrypt.py rrb.pcap --key 0123456789abcdef0123456789abcdef --unique
```

Example output:

```
upstream type=1 (pull) 02:11:11:11:11:05 -> 02:22:22:22:22:05 [eth 02:11:11:11:11:05]: decrypted, 30 bytes, R0KH-ID=022222222205, R1KH-ID=02:11:11:11:11:05
unifi    type=1 (pull) 02:22:22:22:22:05 -> ff:ff:ff:ff:ff:ff [eth 02:22:22:22:22:00]: decrypted, 30 bytes, R0KH-ID=021111111105, R1KH-ID=02:22:22:22:22:05
```

It also reads text output from `tcpdump -e -n` (with the hex dump). Frames
that don't decrypt point to a wrong key or another format.


## How it works

```
 hostapd (OpenWrt)              rrb-unifi                     UniFi AP
 ft_iface=vft0 --- veth --- vft1 <-> translate <-> LAN bridge --- LAN ---
                 (upstream format)               (UniFi format)
```

- hostapd is told to use `ft_iface=vft0`, one end of a veth pair, for all its
  inter-AP messages. OpenWrt's hostapd supports the `ft_iface` option.
- `rrb-unifi` listens on the other end (`vft1`) and on the LAN bridge:
  - from hostapd: insert the source and destination BSSID, send to the LAN
  - from a UniFi AP: strip them, hand the message to hostapd with those
    BSSIDs as the Ethernet addresses
- The encrypted content is never touched. The script doesn't need the key.

Nothing about your setup is hardcoded. At startup the translator reads the
running hostapd configs (`/var/run/hostapd-*.conf`) and serves every BSS
whose `ft_iface` is `vft0`:

- the BSSIDs come from those BSSes' `bssid=` lines
- the LAN interface is the one OpenWrt generated for them before the
  `ft_iface=vft0` override: the bridge of their network, for example
  `br-lan`, `br-home` or `br-lan.10`

It waits until those configs exist and the BSSes are up, then only waits for
messages. It doesn't poll anything while running.

Both FT key distribution modes then work:

- pull: OpenWrt asks UniFi for the key (client first connected to UniFi)
- push: OpenWrt sends the key to UniFi right after the client's first login
  on OpenWrt, so the UniFi AP already has it when the client roams


## Files

| File | Installed as | Description |
|---|---|---|
| `rrb-unifi.uc` | `/usr/sbin/rrb-unifi.uc` | The translator daemon (ucode). Converts RRB-OUI frames between hostapd's private veth link and the LAN, adding or removing UniFi's 12-byte header. |
| `rrb-unifi.init` | `/etc/init.d/rrb-unifi` | procd init script. Starts the translator at boot, restarts it if it stops, and restarts it when the wireless or network config changes. `/etc/init.d/rrb-unifi check` shows what it derives from the running config. |
| `rrb-unifi.config` | `/etc/config/rrb-unifi` | Optional settings: verbose logging, veth names, LAN interface override. All have defaults. |
| `rrb-unifi-setup` | `/usr/sbin/rrb-unifi-setup` | Setup tool (shell). Installs everything, reads the 802.11r settings from the UniFi AP, checks both sides against each other and configures OpenWrt from the UniFi values. Also uninstalls. |
| `tools/rrb-decrypt.py` | (runs on a PC) | Diagnostic tool. Decrypts captured RRB-OUI frames with your r0kh/r1kh key and shows which format each AP uses. Optional; not needed for normal use. |
| `LICENSE` | | GNU General Public License v3.0. |


## Tested with

- OpenWrt **24.10.4** and **25.12.6** on a BT Home Hub 5A (lantiq/xrx200),
  full `wpad-mbedtls`
- UniFi U7 Lite, firmware 8.7.11
- WPA2-PSK, FT over the air (`ft_over_ds=0`), no 802.11w
- Samsung Galaxy S24 (One UI 8.5)

What was tested on which version:

| | 24.10.4 (opkg) | 25.12.6 (apk) |
|---|---|---|
| Manual installation | yes | no (the tool was used) |
| `rrb-unifi-setup install` | yes, clean install | yes, after the upgrade, and a second run (nothing to do) |
| `collect`, `verify`, `apply` | yes | `collect` and `verify` (the config was kept by the upgrade, so `apply` had nothing to do) |
| `rrb-unifi-setup uninstall --remove-packages` | yes, back to the exact pre-install config | no |
| Walk tests, push and pull | yes | yes |
| Pull right after a reboot | yes | no |
| hostapd restart, custom `ifname` | yes | no |
| Firmware upgrade with the project installed | 24.10.4 to 25.12.6, see [After a firmware upgrade](#after-a-firmware-upgrade) | |

Not tested yet:

- the setup tool's interactive prompts (the tests used `--yes`), and the
  automatic network restore actually firing
- the basic wpad variant (`wpad-basic-*`)
- more than one UniFi AP, `--ssid`
- WPA3/SAE, 802.11w, other UniFi models, other OpenWrt devices
- several OpenWrt APs with the translator

Reports are welcome.


## Requirements

- OpenWrt 24.10 or newer, with hostapd/wpad (see
  [Which wpad package?](#which-wpad-package))
- The packages `ucode-mod-socket` and `kmod-veth`. The setup tool installs
  them, so the OpenWrt AP needs internet access during the install.
- SSH access to the UniFi AP, to read its FT settings (Network app: Settings,
  System, Advanced, Device SSH Authentication). The setup tool uses
  OpenWrt's built-in SSH client (`dbclient`), nothing extra is needed.
- The OpenWrt AP and the UniFi AP on the same layer-2 network (same VLAN):
  the key messages are plain Ethernet frames, not IP
- The same SSID, password and security type on both vendors, with Fast
  Roaming enabled in UniFi


### Which wpad package?

OpenWrt builds hostapd (the Wi-Fi access point daemon, packaged as `wpad`)
in variants. Stock images ship the **basic** one, `wpad-basic-mbedtls` on
24.10 and 25.12.

- **Basic** (`wpad-basic-mbedtls`, `-openssl`, `-wolfssl`) includes 802.11r
  fast roaming, which is all this project needs. OpenWrt's build config for
  it has `CONFIG_IEEE80211R=y`. Note: the tests so far used the full variant,
  so basic is expected to work but hasn't been tested yet.
- **Full** (`wpad-mbedtls`, `wpad-openssl`, `wpad-wolfssl`) is needed only
  for features basic leaves out. The one that matters most for roaming setups
  is **802.11v** (WNM; options such as `bss_transition` and
  `wnm_sleep_mode`): basic is built without it (`#CONFIG_WNM=y`). Full also
  adds WPA-Enterprise/EAP and the RADIUS server, mesh and DPP.

The full variant is much bigger. On a BT Home Hub 5A (mips, 25.12.6) the
binary is about 1.55 MB, against 0.9 MB for basic. On devices with little
flash (8 MB or less) it may not fit, which is why the setup tool never
installs it by itself. Check the free space with `df -h /overlay` before
switching.

Check which one you have:

```sh
apk info | grep wpad              # OpenWrt 25.12 and newer
opkg list-installed | grep wpad   # OpenWrt 24.10
```

**Watch out when upgrading the firmware.** A sysupgrade installs the image's
default packages, so a full wpad goes back to basic. If your Wi-Fi config
uses an option that only the full variant knows (for example
`option bss_transition '1'` from enabling 802.11v), hostapd refuses the
whole config and **the AP has no Wi-Fi after the upgrade**:

```
hostapd: Line 45: unknown configuration item 'bss_transition'
hostapd: hostapd.add_iface failed for phy phy0 ifname=phy0-ap0
```

There are two ways out. Run either from a wired connection, because Wi-Fi
on that AP restarts:

- Keep basic and remove the option (you lose 802.11v), for example:
  `uci delete wireless.<section>.bss_transition; uci commit wireless; wifi up`
- Switch back to the full variant with the same crypto library. With apk it
  is one transaction, and the running hostapd must be restarted because it
  keeps the old binary in memory:

  ```sh
  apk add wpad-mbedtls '!wpad-basic-mbedtls' && /etc/init.d/wpad restart && wifi up
  ```

  With opkg (24.10) remove and install are separate steps, so download first
  to avoid ending up without hostapd (untested):

  ```sh
  cd /tmp && opkg update && opkg download wpad-mbedtls &&
    opkg remove wpad-basic-mbedtls && opkg install /tmp/wpad-mbedtls_*.ipk &&
    /etc/init.d/wpad restart && wifi up
  ```

`rrb-unifi-setup verify` reports a hostapd that isn't running the BSSes;
`logread -e hostapd` shows why.


## Installation

### Quick install with rrb-unifi-setup (recommended)

The setup tool runs on the OpenWrt AP. It does every step of the manual
installation below, and it checks everything instead of trusting it. You log
in to each device once: to OpenWrt to run the tool, and to the UniFi AP when
the tool asks for its SSH password. It works the same on OpenWrt 24.10 (opkg)
and 25.12 (apk).

Run it from a wired connection to the OpenWrt AP: `apply` restarts its Wi-Fi.

1. Download this repository to your PC (`git clone`, or Code > Download ZIP).
   From its folder, copy the four files to the OpenWrt AP and log in there:

   ```sh
   scp -O rrb-unifi-setup rrb-unifi.uc rrb-unifi.init rrb-unifi.config root@OPENWRT_IP:/tmp/
   ssh root@OPENWRT_IP
   ```

   `-O` makes scp use the classic protocol, which OpenWrt's SSH server
   (dropbear) understands. Without it, OpenSSH 9 and newer (also the one
   in Windows) use SFTP, which fails unless an SFTP server is installed on
   the AP.

2. Install the packages, the translator and the veth pair:

   ```sh
   sh /tmp/rrb-unifi-setup install
   ```

   It asks before it installs packages and before it changes
   `/etc/config/network`. After the network reload, press Enter within 120
   seconds to keep the change. Without that confirmation, for example because
   the change cut your SSH connection, the previous network config is
   restored automatically. The tool copies itself to
   `/usr/sbin/rrb-unifi-setup`, so from now on you can run it as
   `rrb-unifi-setup`. Running `install` again is safe: it updates the
   translator files, keeps your `/etc/config/rrb-unifi`, and installs or
   creates only what is missing.

3. Read the UniFi AP. Use the device SSH user from the UniFi Network app
   (Settings, System, Advanced, Device SSH Authentication):

   ```sh
   rrb-unifi-setup collect USER@UNIFI_IP
   ```

   The first time, the SSH client asks you to accept the UniFi AP's host key
   and stores it in `/root/.ssh/known_hosts`. Then it runs one read-only
   script on the UniFi AP. It reads the fast-roaming settings and the FT key,
   but only a SHA-256 hash of the Wi-Fi password. The result stays in RAM
   (`/tmp/rrb-unifi-setup`, readable only by root), so it is gone after a
   reboot: run `collect` again before the next `verify` or `apply`. Run it
   once per UniFi AP.

4. Check both sides:

   ```sh
   rrb-unifi-setup verify
   ```

   Every check is reported as `OK`, `FIX` (wrong on OpenWrt; `apply` corrects
   it) or `FAIL` (needs you, for example a different Wi-Fi password or
   security type on the two sides; these are never changed automatically).

5. Configure OpenWrt from the UniFi values and start the translator:

   ```sh
   rrb-unifi-setup apply
   ```

   It shows the exact changes (keys hidden) and asks before it applies them.
   It saves the previous config in `/etc/rrb-unifi-setup/`, and the original
   values of every option it changes, for uninstall. Afterwards it verifies
   again, including the running hostapd config and that the UniFi AP is on
   the same LAN.

Then do the walk tests in [Testing](#testing). Run `rrb-unifi-setup verify`
again whenever something changed on either side. If the UniFi side changed,
run `collect` first.

If several SSIDs have fast roaming, add `--ssid NAME` to `verify` and `apply`.

`--yes` answers every question with yes, for scripted use. Then nothing
waits for Enter after a network reload: confirm the change from a **new** SSH
session within 120 seconds with `rrb-unifi-setup confirm`, or it is restored.

### After a firmware upgrade

A plain sysupgrade keeps the settings and the project's files (they are in
`/etc/sysupgrade.conf`), but not the packages. Until they are back, the veth
is missing and hostapd can't start the BSSes that use it, so **the OpenWrt AP
has no Wi-Fi after the upgrade**. The translator fails too, and procd stops
restarting it after 5 tries. From a wired connection:

```sh
rrb-unifi-setup install              # reinstalls the packages, recreates the veth
wifi up                              # starts the BSSes that failed
/etc/init.d/rrb-unifi restart
rrb-unifi-setup collect USER@UNIFI_IP   # the collected data was in RAM
rrb-unifi-setup verify
```

If the Wi-Fi still doesn't come up, check `logread -e hostapd`. A firmware
image can replace a full wpad with the basic one; see
[Which wpad package?](#which-wpad-package). That happened on the 24.10.4 to
25.12.6 test upgrade. `wifi reload` is no replacement for `wifi up` here: it
doesn't restart a BSS that failed.

Attended Sysupgrade (ASU) builds an image with your installed packages and
avoids most of this (untested with this project).

### Manual installation

These are the steps the setup tool performs, for reference or if you prefer
doing them by hand.

### 1. Read the FT settings from the UniFi AP

SSH into the UniFi AP and find the hostapd config of your SSID:

```sh
grep -l "ssid=YOUR_SSID" /etc/hostapd/*.cfg
grep -E 'mobility_domain|r0kh|r1kh|nas_identifier|iapp_key|ft_over_ds' /etc/hostapd/wifiXapY.cfg
iw dev | grep -E 'Interface|addr|ssid'
```

Note:

- `mobility_domain`, for example `a1b2`
- the key from the `r0kh=`/`r1kh=` lines (32 hex characters, the same as `iapp_key`)
- the BSSID of each UniFi radio broadcasting your SSID (`addr` in `iw dev`),
  for example `02:22:22:22:22:05` and `02:22:22:22:22:02`.
  `nas_identifier=$bssid` means each radio's R0KH-ID is its BSSID without colons.

### 2. Install the packages on OpenWrt

OpenWrt 24.10 (opkg):

```sh
opkg update && opkg install ucode-mod-socket kmod-veth
```

OpenWrt 25.x and newer (apk):

```sh
apk update && apk add ucode-mod-socket kmod-veth
```

Then check:

```sh
ucode -l socket -e 'print(socket.AF_PACKET, "\n")'    # must print 17
```

### 3. Create the veth pair

```sh
uci set network.vft=device
uci set network.vft.type='veth'
uci set network.vft.name='vft0'
uci set network.vft.peer_name='vft1'
uci set network.ftlink=interface
uci set network.ftlink.proto='none'
uci set network.ftlink.device='vft0'
uci set network.ftpeer=interface
uci set network.ftpeer.proto='none'
uci set network.ftpeer.device='vft1'
uci commit network && /etc/init.d/network reload
cat /sys/class/net/vft0/operstate /sys/class/net/vft1/operstate    # both "up"
```

`vft0` and `vft1` are names this project chooses. If they clash with
something on your device, pick others and set `ft_iface`/`peer_iface` in
`/etc/config/rrb-unifi` to match.

### 4. Copy the files

```sh
scp -O rrb-unifi.uc root@OPENWRT_IP:/usr/sbin/rrb-unifi.uc
scp -O rrb-unifi.init root@OPENWRT_IP:/etc/init.d/rrb-unifi
scp -O rrb-unifi.config root@OPENWRT_IP:/etc/config/rrb-unifi
```

On OpenWrt:

```sh
chmod +x /usr/sbin/rrb-unifi.uc /etc/init.d/rrb-unifi
```

### 5. Configure 802.11r on OpenWrt

Set the first four variables to your values from step 1. The loop finds every
OpenWrt AP interface with your SSID by itself, whatever its section name,
interface name or radio, and uses its own BSSID as `nasid`.

```sh
SSID='YOUR_SSID'
KEY=0123456789abcdef0123456789abcdef
MDID=a1b2
# every UniFi BSSID broadcasting your SSID, separated by spaces
UNIFI_BSSIDS='02:22:22:22:22:05 02:22:22:22:22:02'

for s in $(uci show wireless | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface$/\1/p'); do
  [ "$(uci -q get wireless.$s.ssid)" = "$SSID" ] || continue
  [ "$(uci -q get wireless.$s.mode)" = ap ] || continue
  ifname=$(ubus call network.wireless status | jsonfilter -e "@.*.interfaces[@.section='$s'].ifname")
  bssid=$(cat /sys/class/net/$ifname/address 2>/dev/null)
  [ -n "$bssid" ] || { echo "$s: interface not up, skipped"; continue; }
  echo "$s: $ifname $bssid"
  uci set wireless.$s.ieee80211r='1'
  uci set wireless.$s.mobility_domain="$MDID"
  uci set wireless.$s.ft_over_ds='0'
  uci set wireless.$s.ft_psk_generate_local='0'
  uci set wireless.$s.pmk_r1_push='1'
  uci set wireless.$s.nasid="$(echo $bssid | tr -d :)"
  uci -q delete wireless.$s.r0kh; uci -q delete wireless.$s.r1kh
  uci -q delete wireless.$s.hostapd_bss_options
  # one r0kh + r1kh line per UniFi radio (needed for push)
  for b in $UNIFI_BSSIDS; do
    uci add_list wireless.$s.r0kh="$b,$(echo $b | tr -d :),$KEY"
    uci add_list wireless.$s.r1kh="$b,$b,$KEY"
  done
  # wildcards, the same as the UniFi side uses
  uci add_list wireless.$s.r0kh="ff:ff:ff:ff:ff:ff,*,$KEY"
  uci add_list wireless.$s.r1kh="00:00:00:00:00:00,00:00:00:00:00:00,$KEY"
  # send inter-AP messages through the translator
  uci add_list wireless.$s.hostapd_bss_options='ft_iface=vft0'
done
uci changes wireless    # review
uci commit wireless && wifi reload
```

Each matching interface should be listed once. If none is listed, check the
SSID spelling, and that the interfaces are up.

### 6. Start the translator

`wifi reload` returns before the new config is written. Wait about 10
seconds, then:

```sh
/etc/init.d/rrb-unifi check
```

Expected (your names may differ, that's fine):

```
hostapd configs in /var/run:
  phy0-ap0     hostapd-phy0.conf    ft_iface=br-lan,vft0 -> served, BSSID 02:11:11:11:11:05, hostapd up
  phy1-ap0     hostapd-phy1.conf    ft_iface=br-lan,vft0 -> served, BSSID 02:11:11:11:11:02, hostapd up
veth: vft0 (hostapd) <-> vft1 (rrb-unifi)
LAN interface: br-lan (derived)
check OK
```

Every interface with your SSID must be "served" and "up". Then:

```sh
/etc/init.d/rrb-unifi enable
/etc/init.d/rrb-unifi start
logread -e rrb-unifi
```

Expected:

```
rrb-unifi: running: hostapd side vft1 (ft_iface vft0), lan side br-lan, BSSes: phy0-ap0=02:11:11:11:11:05 phy1-ap0=02:11:11:11:11:02
```

To keep the files across sysupgrade (`/etc/config/rrb-unifi` is kept
automatically):

```sh
printf '/usr/sbin/rrb-unifi.uc\n/etc/init.d/rrb-unifi\n/etc/rc.d/S99rrb-unifi\n' >> /etc/sysupgrade.conf
```


## Testing

Turn on per-frame logging and watch the log:

```sh
uci set rrb-unifi.main.verbose='1' && uci commit rrb-unifi && /etc/init.d/rrb-unifi restart
logread -f -e rrb-unifi
```

1. Next to the OpenWrt AP, turn the client's Wi-Fi off and on, then walk to
   the UniFi AP. You should see push messages (`type=3`, one per UniFi radio)
   right after the login, and a fast roam.
2. Next to the UniFi AP, turn Wi-Fi off and on, then walk to the OpenWrt AP.
   You should see a pull (`type=1` out, `type=2` in) and a fast roam. The
   first exchange after a restart is preceded by sequence messages
   (`type=4`, `type=5`).

Message types: 1 pull, 2 pull response, 3 push, 4 sequence request,
5 sequence response.

If test 2 shows a fast roam but no pull, the OpenWrt AP already had the key.
With a Wi-Fi password (FT-PSK) the roaming key has no random part: turning
Wi-Fi off and on gives the same key, and hostapd keeps keys it fetched for
days. To see a real pull, empty that cache by restarting hostapd on OpenWrt
(`wifi down; wifi up`, or a reboot), then repeat test 2. A plain `wifi reload`
does nothing when the config hasn't changed.

On the UniFi AP, a fast roam shows as `"auth_algo": "ft"` in `logread`. A
failed one shows repeated `auth_algo: ft` failures followed by `auth_algo: open`.
On OpenWrt, a fast roam shows as `AP-STA-CONNECTED <client MAC> auth_alg=ft`
(`logread -e hostapd`); a full login shows `auth_alg=open`. On the HH5A,
every fast roam is preceded by `nl80211: kernel reports: key addition failed`.
That message is harmless: the roam completes in the same second.

Turn per-frame logging off again when done:

```sh
uci set rrb-unifi.main.verbose='0' && uci commit rrb-unifi && /etc/init.d/rrb-unifi restart
```


## Troubleshooting

- Run `/etc/init.d/rrb-unifi check` first. It shows every hostapd BSS, which
  ones the translator serves, and the LAN interface, and names what's wrong.
- `logread -e rrb-unifi` shows startup errors. After 5 failed starts in a row
  procd stops retrying; fix the cause and run `/etc/init.d/rrb-unifi restart`.
- `ignoring unrecognized RRB frames from ...`: a device on the LAN sends
  inter-AP messages the translator can't parse. If it's a UniFi AP, its
  firmware may have changed the format.
- `ignoring upstream-format RRB frames from ...`: another OpenWrt AP without
  the translator. Install it there too.
- If hostapd can't start a BSS because `vft0` didn't exist yet when Wi-Fi came
  up, the translator runs `wifi up` once per boot after waiting 30 s.
  (`wifi reload` would not help: it doesn't restart a BSS that failed.) In
  the reboot tests the veth was always up before Wi-Fi, so this fallback
  hasn't been needed yet.
- No Wi-Fi at all after a firmware upgrade: see
  [After a firmware upgrade](#after-a-firmware-upgrade).


## Notes and limitations

- If you recreate the SSID in UniFi, its FT key may change. Update `KEY` on
  OpenWrt (rerun step 5).
- If UniFi BSSIDs change (new SSIDs, radio changes) or you add another UniFi
  AP, add its BSSIDs to the `r0kh`/`r1kh` lists (rerun step 5). The
  translator itself needs no changes.
- After changing the wireless config by hand with `wifi reload`, run
  `/etc/init.d/rrb-unifi restart` if BSSIDs or the network changed. Changes
  applied with LuCI (or `reload_config`) restart it automatically.
- `kmod-veth` and `ucode-mod-socket` are not kept by a plain sysupgrade, and
  a full wpad can go back to basic: the OpenWrt AP has no Wi-Fi until you
  follow [After a firmware upgrade](#after-a-firmware-upgrade).
- Only RRB-OUI (0x88b7) is translated. FT over the DS uses ethertype 0x890d and
  is not handled; keep `ft_over_ds=0`, which is the UniFi default.
- With several OpenWrt APs, each one needs the translator. OpenWrt-to-OpenWrt
  key exchange also goes through it in UniFi format, which is untested.
- A UniFi firmware update could change the format again. If roaming to UniFi
  breaks after an update, check the UniFi log for `RRB-OUI frame too short`.


## Uninstall

With the setup tool:

```sh
rrb-unifi-setup uninstall --remove-packages
```

It restores the original values of the Wi-Fi options it changed (or, after a
manual install, switches back to `ft_psk_generate_local=1`), removes the veth
pair with the same 120-second confirmation as `install`, and removes the
files, the `sysupgrade.conf` lines and, with `--remove-packages`, the two
packages. Tested on 24.10: the wireless and network config were back to
exactly the state before the install.

Left in place: the tool itself (`/usr/sbin/rrb-unifi-setup`), its backups and
original values (`/etc/rrb-unifi-setup/`), and the UniFi host key from
`collect` in `/root/.ssh/known_hosts`. The veth kernel module stays loaded
until the next reboot. To remove the rest:

```sh
rm -r /etc/rrb-unifi-setup /usr/sbin/rrb-unifi-setup
```

By hand:

```sh
/etc/init.d/rrb-unifi stop; /etc/init.d/rrb-unifi disable
for s in $(uci show wireless | sed -n 's/^wireless\.\([^.]*\)\.hostapd_bss_options=.*ft_iface=vft0.*/\1/p'); do
  uci set wireless.$s.ft_psk_generate_local='1'
  uci -q delete wireless.$s.pmk_r1_push; uci -q delete wireless.$s.r0kh
  uci -q delete wireless.$s.r1kh; uci -q delete wireless.$s.nasid
  uci -q delete wireless.$s.hostapd_bss_options
done
uci commit wireless && wifi reload
uci -q delete network.vft; uci -q delete network.ftlink; uci -q delete network.ftpeer
uci commit network && /etc/init.d/network reload
rm /usr/sbin/rrb-unifi.uc /etc/init.d/rrb-unifi /etc/config/rrb-unifi
sed -i '/rrb-unifi/d' /etc/sysupgrade.conf
```

Then remove the packages if nothing else needs them:
`opkg remove ucode-mod-socket kmod-veth` (24.10) or
`apk del ucode-mod-socket kmod-veth` (25.12).


## Changes

### 1.1

- Nothing about the local setup is hardcoded any more. The served BSSes,
  their BSSIDs and the LAN interface are read from the running hostapd
  configs. 1.0 assumed `br-lan` and interface names like `phy0-ap0`. With
  other names it failed, sometimes silently, and roaming was then worse than
  without it.
- New setup tool `rrb-unifi-setup`: install, collect (reads the UniFi AP
  over SSH), verify (both sides and the running state), apply, uninstall.
  Network changes revert automatically unless they are confirmed.
- New `/etc/init.d/rrb-unifi check`.
- Settings moved to `/etc/config/rrb-unifi` (verbose logging, overrides).
- The boot check (one `wifi up` if a BSS failed to start; 1.0 used
  `wifi reload`, which doesn't restart a failed BSS) moved into the
  daemon and no longer uses hardcoded interface names.
- Restarts on wireless/network config changes; stops retrying after 5 quick
  failures instead of restarting forever.
- Logs unrecognized RRB frames from the LAN once per sender.
- `install` recreates a veth that is configured but missing (after a
  firmware upgrade). `check` and `verify` report a hostapd BSS that isn't
  running as an error.
- README: the 802.11r setup loop finds your interfaces by SSID; `apk` for
  OpenWrt 25; firmware upgrade steps; which wpad variant is needed.
- Tested on OpenWrt 24.10.4 and 25.12.6 with the HH5A + U7 Lite; details in
  [Tested with](#tested-with):
  - push and pull walk tests on both versions, including a pull right after
    a reboot (24.10)
  - hostapd restart (`wifi down; wifi up`) with the translator running
  - a custom interface name (`ifname`)
  - reboot: the translator started by itself once the BSSes were up
  - the setup tool on 24.10: uninstall back to the pre-project state, clean
    install (packages from the feed), collect, apply. The result was
    identical to the hand-made config, and the walk tests passed.
  - sysupgrade 24.10.4 to 25.12.6 with the project installed, recovered with
    `rrb-unifi-setup install` (apk) plus the wpad swap; walk tests passed on
    25.12.6

**Upgrading from 1.0:** run the setup tool (`install`, `collect`, `verify`, `apply`), or copy the three files (step 4), then
`/etc/init.d/rrb-unifi check` and `/etc/init.d/rrb-unifi restart`. The wireless
and network config stay as they are.


## Disclaimer

This project is not affiliated with or endorsed by Ubiquiti Inc. or the
OpenWrt project. UniFi is a trademark of Ubiquiti Inc. It is used here only
to describe which devices this works with. Nothing on the UniFi AP is modified;
the fix runs entirely on the OpenWrt side.


## License

Copyright (C) 2026 d-malinowski

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

The full license text is in [LICENSE](LICENSE).
