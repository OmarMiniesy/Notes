### General Notes

[[Wi-Fi Connection|WiFi]] networks, also known as `802.11` traffic can only be examined using a [[IDS & IPS|WIDS/WIPS]] or through a wireless interface equipped with monitor mode.
- *Monitor mode* is like promiscuous mode on [[Wireshark]].

---
### Monitor Mode

To check the wireless interfaces on a Linux machine:
- Check if the `mode` is set to `monitor`. 
```bash
iwconfig
```

> There are several techniques to enter *monitor mode* on an identified wireless interface.

To enter monitor mode on one of the identified wireless interfaces from above, we can use `airodump-ng`.
```bash
sudo airmon-ng start <INTERFACE>
```

We can also deactivate the interface, then open it in monitor mode.
```bash
sudo ifconfig <INTERFACE> down
sudo iwconfig <INTERFACE> mode monitor
sudo ifconfig <INTERFACE> up
```

To capture traffic from the wireless interface:
```bash
sudo airodump-ng -c <CHANNEL> --bssid <BSSID> <INTERFACE> -w raw 
```
- The `-c` is the channel of the [[Device Types#Access Point (AP)|Access Point]].
- The `-bssid` is the [[Identifiers#Basic Service Set Identifier (BSSID)|BSSID]], or MAC address of the Access Point.
- The `-w` is the output file.

---
### Using [[Wireshark]]

To filter for a single Access Point's BSSID, we can use the [[Wireshark]] filter `wlan.bssid`.
- This [sheet](https://semfionetworks.com/wp-content/uploads/2021/04/wireshark_802.11_filters_-_reference_sheet.pdf) has the Wireshark filters for `802.11`.
###### Detecting the [[Deauthentication Attack]]

To filter for deauthentication frames:
```
wlan.bssid == xx:xx:xx:xx:xx:xx and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```
- We specify management frames using `00` and then deauthentication frames using `12`.

We can fine tune this search to look for *reason code 7* which is used by tools during the deauthentication attack.
```
wlan.bssid == xx:xx:xx:xx:xx:xx and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```

> Sometimes attacker can change the reason code to avoid being detected. Try other reason codes during detection.

###### Detecting Failed Authentication

Attackers can sometimes bombard the Access Point with many association requests to try and connect from one device:
```
(wlan.bssid == XX:XX:XX:XX:XX:XX) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11)
```
- Filter for all management frames: `wlan.fc.type == 0`.
- Filter for Association Requests: `wlan.fc.type_subtype == 0`.
- Filter for Association Responses: `wlan.fc.type_subtype == 1`.
- Filter for Reassociation Requests:` wlan.fc.type_subtype == 2`.

###### Detecting the [[Evil Twin Attack]]

We can check for *beacon frames* that the rogue access point sends to convince clients to connect to it.
```
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```
- Where subtype 8 is for beacon frames.

> Checking also the `RSN` information under the *Tagged Parameters* section in the packet data. If it is not there, then this is a sign of suspicious behavior.

---
