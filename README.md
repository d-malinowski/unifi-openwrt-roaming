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

The translator, `rrb-unifi`, is a small ucode script (about 150 lines) that
runs on the OpenWrt AP. It is named after RRB, the messages hostapd uses to
exchange roaming keys between APs. It translates those messages between the
two vendors. It needs no compiling and no Python, so it fits even on old
devices. It adds two small packages that are already in the OpenWrt feeds.


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
tcpdump -i br-lan -e -n -w /tmp/rrb.pcap 'ether proto 0x88b7'

# on a PC (pip install cryptography)
python3 tools/rrb-decrypt.py rrb.pcap --key 0123456789abcdef0123456789abcdef --unique
```

Example output:

```
upstream type=1 (pull) 90:72:82:aa:bb:2b -> 92:30:66:aa:bb:26 [eth 90:72:82:aa:bb:2b]: decrypted, 30 bytes, R0KH-ID=923066aabb26, R1KH-ID=90:72:82:aa:bb:2b
unifi    type=1 (pull) 92:30:66:aa:bb:26 -> ff:ff:ff:ff:ff:ff [eth 8c:30:66:aa:bb:24]: decrypted, 30 bytes, R0KH-ID=907282aabb2b, R1KH-ID=92:30:66:aa:bb:26
```

It also reads text output from `tcpdump -e -n` (with the hex dump). Frames
that don't decrypt point to a wrong key or another format.


## How it works

```
 hostapd (OpenWrt)              rrb-unifi                     UniFi AP
 ft_iface=vft0 --- veth --- vft1 <-> translate <-> br-lan --- LAN ---
                 (upstream format)            (UniFi format)
```

- hostapd is told to use `ft_iface=vft0`, one end of a veth pair, for all its
  inter-AP messages. OpenWrt's hostapd supports the `ft_iface` option.
- `rrb-unifi` listens on the other end (`vft1`) and on `br-lan`:
  - from hostapd: insert the source and destination BSSID, send to the LAN
  - from a UniFi AP: strip them, hand the message to hostapd with those
    BSSIDs as the Ethernet addresses
- The encrypted content is never touched. The script doesn't need the key.
- Local BSSIDs are detected automatically (`/sys/class/net/phy*-ap*`).

Both FT key distribution modes then work:

- pull: OpenWrt asks UniFi for the key (client first connected to UniFi)
- push: OpenWrt sends the key to UniFi right after the client's first login
  on OpenWrt, so the UniFi AP already has it when the client roams


## Tested with

- OpenWrt 24.10.4 on a BT Home Hub 5A (lantiq/xrx200), `wpad-mbedtls`
- UniFi U7 Lite, firmware 8.7.11
- WPA2-PSK, FT over the air (`ft_over_ds=0`), no 802.11w
- Samsung Galaxy S24 (One UI 8.5)

Other setups probably work but are untested. That includes more UniFi APs,
WPA3/SAE, other OpenWrt versions and other UniFi models. Reports are welcome.


## Requirements

- OpenWrt 24.10 or newer with full hostapd/wpad (`wpad-mbedtls`,
  `wpad-openssl`, `wpad-wolfssl`; the "basic" variants also include 802.11r)
- The packages `ucode-mod-socket` and `kmod-veth`
- SSH access to the UniFi AP, to read its FT settings (Network app: Settings,
  System, Advanced, Device SSH Authentication)
- The same SSID, password and security type on both vendors, with Fast
  Roaming enabled in UniFi


## Installation

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
  for example `92:30:66:aa:bb:26` and `92:30:66:aa:bb:25`.
  `nas_identifier=$bssid` means each radio's R0KH-ID is its BSSID without colons.

### 2. Install the packages on OpenWrt

```sh
opkg update && opkg install ucode-mod-socket kmod-veth
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

### 4. Copy the script

```sh
scp -O rrb-unifi.uc root@OPENWRT_IP:/usr/sbin/rrb-unifi.uc
scp -O rrb-unifi.init root@OPENWRT_IP:/etc/init.d/rrb-unifi
```

On OpenWrt:

```sh
chmod +x /usr/sbin/rrb-unifi.uc /etc/init.d/rrb-unifi
```

If your OpenWrt AP uses interface names other than `phy0-ap0 phy1-ap0`, edit
`BSS_IFACES` in `/etc/init.d/rrb-unifi`. It is only used by the boot check.

### 5. Configure 802.11r on OpenWrt

Replace the example values with your own:

- `KEY`: the key from the UniFi config
- the UniFi BSSIDs and their R0KH-IDs (BSSID without colons)
- `nasid`: each OpenWrt radio's BSSID without colons (`iw dev` on OpenWrt)
- `mobility_domain`: the value from the UniFi config

```sh
KEY=0123456789abcdef0123456789abcdef
for i in default_radio0 default_radio1; do
  uci set wireless.$i.ieee80211r='1'
  uci set wireless.$i.mobility_domain='a1b2'
  uci set wireless.$i.ft_over_ds='0'
  uci set wireless.$i.ft_psk_generate_local='0'
  uci set wireless.$i.pmk_r1_push='1'
  uci -q delete wireless.$i.r0kh; uci -q delete wireless.$i.r1kh
  uci -q delete wireless.$i.hostapd_bss_options
  # one r0kh + r1kh line per UniFi radio (needed for push)
  uci add_list wireless.$i.r0kh="92:30:66:aa:bb:26,923066aabb26,$KEY"
  uci add_list wireless.$i.r0kh="92:30:66:aa:bb:25,923066aabb25,$KEY"
  uci add_list wireless.$i.r1kh="92:30:66:aa:bb:26,92:30:66:aa:bb:26,$KEY"
  uci add_list wireless.$i.r1kh="92:30:66:aa:bb:25,92:30:66:aa:bb:25,$KEY"
  # wildcards, the same as the UniFi side uses
  uci add_list wireless.$i.r0kh="ff:ff:ff:ff:ff:ff,*,$KEY"
  uci add_list wireless.$i.r1kh="00:00:00:00:00:00,00:00:00:00:00:00,$KEY"
  # send inter-AP messages through the translator
  uci add_list wireless.$i.hostapd_bss_options='ft_iface=vft0'
done
uci set wireless.default_radio0.nasid='907282aabb2b'
uci set wireless.default_radio1.nasid='907282aabb2a'
uci commit wireless && wifi reload
```

`wifi reload` returns before the new config is written, so wait about 10
seconds, then check:

```sh
grep -E 'ft_iface|nas_identifier|r0kh|r1kh' /var/run/hostapd-phy*.conf
ubus list | grep hostapd
```

Each config should contain `ft_iface=br-lan` followed by `ft_iface=vft0`. The
last one wins. All hostapd BSSes must still be listed.

### 6. Start the translator

```sh
/etc/init.d/rrb-unifi enable
/etc/init.d/rrb-unifi start
logread -e rrb-unifi
```

Expected:

```
rrb-unifi: running: hostapd side vft1, lan side br-lan, local BSSIDs: 90:72:82:aa:bb:2b 90:72:82:aa:bb:2a
```

To keep the files across sysupgrade:

```sh
printf '/usr/sbin/rrb-unifi.uc\n/etc/init.d/rrb-unifi\n/etc/rc.d/S99rrb-unifi\n' >> /etc/sysupgrade.conf
```


## Testing

Set `VERBOSE=1` in `/etc/init.d/rrb-unifi` and run `/etc/init.d/rrb-unifi restart`,
then watch `logread -f -e rrb-unifi`.

1. Next to the OpenWrt AP, turn the client's Wi-Fi off and on, then walk to
   the UniFi AP. You should see push messages (`type=3`) right after the
   login, and a fast roam.
2. Next to the UniFi AP, turn Wi-Fi off and on, then walk to the OpenWrt AP.
   You should see a pull (`type=4`, `type=1` out, `type=5`, `type=2` in) and a
   fast roam.

Message types: 1 pull, 2 pull response, 3 push, 4 sequence request,
5 sequence response.

On the UniFi AP, a fast roam shows as `"auth_algo": "ft"` in `logread`. On
OpenWrt, it shows as `authentication OK (FT)` when log level is raised. A
failed one shows repeated `auth_algo: ft` failures followed by `auth_algo: open`.

Set `VERBOSE=0` again when done.


## Notes and limitations

- If you recreate the SSID in UniFi, its FT key may change. Update `KEY` on
  OpenWrt.
- If UniFi BSSIDs change (new SSIDs, radio changes) or you add another UniFi
  AP, add its BSSIDs to the `r0kh`/`r1kh` lists. The script itself needs no
  changes.
- `kmod-veth` and `ucode-mod-socket` are not kept by a plain sysupgrade.
  Use Attended Sysupgrade, or reinstall them and run
  `/etc/init.d/rrb-unifi enable` afterwards.
- hostapd won't start a BSS if `vft0` doesn't exist when Wi-Fi comes up. The
  init script checks this 30 seconds after boot and runs `wifi reload` once if
  needed.
- Only RRB-OUI (0x88b7) is translated. FT over the DS uses ethertype 0x890d and
  is not handled; keep `ft_over_ds=0`, which is the UniFi default.
- With several OpenWrt APs, each one needs the translator. OpenWrt-to-OpenWrt
  key exchange also goes through it in UniFi format, which is untested.
- A UniFi firmware update could change the format again. If roaming to UniFi
  breaks after an update, check the UniFi log for `RRB-OUI frame too short`.


## Uninstall

```sh
/etc/init.d/rrb-unifi stop; /etc/init.d/rrb-unifi disable
for i in default_radio0 default_radio1; do
  uci set wireless.$i.ft_psk_generate_local='1'
  uci -q delete wireless.$i.pmk_r1_push; uci -q delete wireless.$i.r0kh
  uci -q delete wireless.$i.r1kh; uci -q delete wireless.$i.nasid
  uci -q delete wireless.$i.hostapd_bss_options
done
uci commit wireless && wifi reload
uci -q delete network.vft; uci -q delete network.ftlink; uci -q delete network.ftpeer
uci commit network && /etc/init.d/network reload
rm /usr/sbin/rrb-unifi.uc /etc/init.d/rrb-unifi
```


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
