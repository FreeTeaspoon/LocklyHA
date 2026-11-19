# PGD898S: Lockly Home and Home Assistant audit

Audited against Lockly Home 1.6.2 and a PGD898S reporting lock type 97,
firmware 2.01.96 / raw 00960102, T21 Vision Connect firmware 0228 and camera
firmware 0098. This is a model-specific integration, not a claim of parity
with every Lockly model or every Lockly Home feature.

## Implemented and verified

| Feature | Home Assistant behavior | Evidence |
| --- | --- | --- |
| Lock and unlock | Native lock entity, followed by a fresh hardware status confirmation | Existing v0.8.0b5 physical tests |
| Door contact | Native door entity | Actual open/closed circuit readings |
| Battery | Model-specific S8 voltage estimate and a separate voltage entity | APK defaults and the phone's active Firebase thresholds agree |
| Camera | Locally decoded JPEG/MJPEG; starts when requested and stops after requests cease | Existing real video verification; lifecycle tests |
| Streaming state | Reports active capture instead of a hardcoded `idle` state | Camera lifecycle tests |
| Settings refresh | Button and access-card Refresh; no recurring BLE settings polling | Both `19/01` and `19/02` queried on the lock |
| PIN Genie | Native switch and access-card setting | Settings bit 0; preserves other bits |
| Keypad sound | Native switch and access-card setting | Changed, read back and restored on hardware |
| Auto-lock enable | Native switch; retains the lock's configured delay | Settings bit 3; no unverified timer replacement |
| Bluetooth connection sound | Native switch and access-card setting | Settings2 bit 1, app reference and hardware query |
| Fingerprint enrollment sound | Native switch and access-card setting | Settings2 bit 5, app reference and hardware query |
| Hub doorbell volume | Native select, Mute / Low / High | Changed from High to Low, read back and restored |
| Read owner and PIN entries | Admin-only access card; names, slots and schedules | Named query `2D` decoded on hardware |
| Add PIN | Writes a free guest slot to the physical lock, then reads the list again | Temporary test PIN created in unused slot 41 |
| Edit PIN/name/schedule | Keeps a blank PIN unchanged; validates the resulting hardware entry | Test PIN changed to a recurring schedule with its PIN retained |
| Delete PIN | Deletes only the selected supported slot; protects owner/special slots | Test PIN deleted; original entries compared before/after |
| Always / date range / weekly schedules | Encodes in the lock's configured time zone; rejects invalid ranges | App command references, protocol tests and live recurring-schedule test |
| Access history | On-demand bulk `78` query, correct lock time zone, HA Last Access and events | 50 hardware records decoded |
| Credential privacy | PIN inputs travel through an admin-only WebSocket, not HA service calls | Authorization, sanitization and transaction tests |

Settings are read before every change. The write changes only the selected bit;
a subsequent hardware reading must match. PIN operations read the complete list
before and after writing and verify that every other entry is unchanged.
Edit/delete requests include an ephemeral keyed revision token, so a stale card
cannot change a slot that was reused or changed in Lockly Home. A restart requires
a fresh read before editing. The token is not an unkeyed hash of the PIN. Writes
are never automatically replayed after an uncertain result. A rejected operation
must be reviewed with Refresh before retrying.

Reply matching includes settings/PIN subcommands, not just the top-level BLE
opcode. This prevents a delayed group-1 settings reply from satisfying a group-2
query. Parsers validate frame length, header, opcode, subtype, CRC and encrypted
payload alignment, and reject incomplete or ambiguous credential lists.

## Remaining app features and limits

| App feature | Audit result / current support |
| --- | --- |
| Auto-lock delay and alarm timing | App sends separate `12` / alarm commands and caches values locally. No verified hardware readback of the current timer was found. The enable switch preserves that timer; arbitrary delay editing is not exposed. |
| Alarm configuration, safe/welcome/passage modes, slide/sensor controls | Commands and bitmap fields exist across Lockly models. Their semantics and applicability are not verified on this PGD898S; they are not presented as working controls. |
| One-time and delegated/subadmin PINs | Special slots and separate app workflows exist. They are protected from the ordinary-PIN editor; one-time consumption and delegation are not implemented. |
| Fingerprint listing, enrollment, rename and deletion | Separate sensor protocol, not the PIN list. Enrollment needs a person at the sensor and a complete progress/cancel workflow. Not implemented by this release. |
| Offline Access Codes (OAC) | Separate vendor key-generation/sharing workflow. Not implemented. |
| eKeys, account invitations, sharing and access permissions | Vendor account workflows, distinct from writing a hardware PIN. Not implemented. |
| Cloud users and app synchronization | Hardware PIN names/schedules are read directly from the lock. HA does not create an account invitation or promise that the app's cached cloud directory immediately updates. |
| Newer night-vision and radio-diagnostic settings | This hub did not answer `33294` or `33292`. Controls are not exposed for unsupported firmware. |
| Camera audio / two-way talk | Requires additional audio streaming, codec and microphone transport. Current camera is video only. |
| Camera recording controls, SD capacity, clip playback/export | Separate hub storage/playback protocol; not implemented. Existing recordings are untouched. |
| PIR/automatic recording and camera power settings | Present in the camera SDK, not verified for this camera/firmware. Not exposed. |
| Doorbell, motion and tamper push events | BLE/hub unsolicited-event coverage is incomplete. Do not rely on HA as a complete substitute for Lockly Home notifications. |
| Wi-Fi setup, firmware updates, pairing and factory reset | Remain in Lockly Home / physical maintenance workflows. They are not added as ordinary dashboard actions. |
| Owner PIN changes / master-key rotation | Deliberately excluded from the guest editor. Owner slot 0 cannot be changed or deleted through management. |

No cloud `acu/save` response is treated as proof that a PIN reached this lock.
The older cloud-only add/delete services reject Vision operations and direct
users to the verified hardware editor. Guest-list events are sanitized for all
models; raw cloud credential responses are no longer debug-logged.

## Battery findings

The previous 19% reading at 4.78 V came from a generic linear 4.5–6.0 V curve.
That curve does not match this lock's app. Lockly Home uses discrete S8 thresholds
in units of 10 mV:

| At or below | Percentage |
| --- | --- |
| 3.80 V | 0 |
| 4.21 V | 10 |
| 4.61 V | 20 |
| 4.88 V | 30 |
| 5.06 V | 40 |
| 5.18 V | 50 |
| 5.27 V | 60 |
| 5.39 V | 70 |
| 5.53 V | 80 |
| 5.72 V | 90 |
| Above 5.72 V | 100 |

The app also stores a previous percentage and suppresses some small upward
changes. HA uses the verified curve, marks it as an estimate, and does not copy
one user-reported percentage as a calibration point. The app and HA can differ
when their samples or stored histories differ. A binary low/normal flag is no
longer displayed as a fabricated 10%/90% percentage.

These observations establish a calculation error, not a measured rate of battery
drain or proof that the camera caused it. A dashboard with a live picture card
requests frames continuously while open. Use an entity/button that opens the
camera on tap to avoid starting video merely by visiting the dashboard. The
integration stops capture 10 seconds after its last frame request.

## Access card setup

Add `/lockly/management-card.js?v=0.9.0b2` as a JavaScript module under dashboard
resources. Add a manual card:

```yaml
type: custom:lockly-management-card
```

An optional `lock_id` selects a specific supported lock. The card requires a
Home Assistant administrator. Press **Refresh settings & PINs** first. Schedules
show the lock's time zone, which may differ from the browser's. PINs remain
masked while entered, are cleared on submission/removal, and are not returned
by the list endpoint. Leave the PIN blank while editing to retain the old code.

For a battery-conscious camera tile:

```yaml
type: button
entity: camera.living_room_property_camera
name: View front door camera
icon: mdi:cctv
tap_action:
  action: more-info
```

Settings and history are snapshots, refreshed explicitly. There is no recurring
BLE credential/settings/history query on this Vision lock after its initial
history fetch. Public control responses contain only sanitized metadata;
credential values are held only in the transaction's memory.
