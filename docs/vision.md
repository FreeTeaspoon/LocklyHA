# Vision Connect control transport

The PGD898S does not use Secure LINK's REST relay or the WiFi-native MQTT
transport. Upstream issue [#15](https://github.com/Forcky/LocklyHA/issues/15)
records this distinction. The camera hub carries encrypted lock BLE frames
through its PPCS control channel.

## Scope and evidence

The reference is Lockly Home 1.6.2, including its PPCS SDK and CameraApiImpl.
The native SDK was used offline to obtain packet codec vectors. No SDK binary,
APK, account credential, or device record is distributed in this repository.
Live status was verified on PGD898S, lock type 97, T21 hub firmware 0228,
camera firmware 0098. Lock firmware reports 00960102. It returned a locked
bolt, closed door circuit, and an AA battery voltage around 5.2 V.

One HA unlock was confirmed on hardware. The immediate relock ACK still
reported unlocked, but a status query 350 ms later confirmed locked. The
integration now waits for motor completion with up to three read-only status
queries, spaced 500 ms apart. This timing correction has offline regression
coverage; the physical cycle has not been repeated after the correction.
Open-door transitions and unsolicited updates have not yet been verified. The credential-list query returned no usable host
entry on this hardware; commands can use the authenticated account's cloud
host-credential copy instead. Video/audio and guest PIN activation are outside
the validated support in this release.

## Packet and session layout

Decoded packets contain `F1`, a type byte, a big-endian uint16 payload length,
and the payload. The shared application codec key is `U7iuNZEfje`. It is an
application constant, not the hub's individual password. The substitution table
and codec live in `vision.py`. Tests include independent SDK vectors.

The lookup servers are `3.223.181.96`, `p2psg.lockly.com` and `p2pau.lockly.com`,
UDP port 32100. Hello 00 receives 01. Lookup 20 carries the 20-byte device UID
and a local sockaddr; response 40 supplies hub endpoints. Punch 41/42 must
match both an advertised endpoint and the expected UID.

The UID is `!8sI8s`. The sockaddr is unusual: family is big-endian, the port is
little-endian, and the IPv4 bytes are reversed. For example,
`0002dc3ab432a8c00000000000000000` means `192.168.50.180:15068`.

Reliable data uses packet D0 with `D1`, channel, big-endian uint16 sequence and
stream bytes. D1 packets acknowledge named sequences. Channel 0 carries control
messages framed as six little-endian uint32 values: magic 1987479688, payload
size, command, zero, zero, zero.

Command 16 authenticates with the individual hub password padded to 72 bytes.
Passthrough 33118 contains four little-endian uint32 fields, source 2, camera
channel 0, message type 0, BLE frame length, then a frame padded to 100 bytes.
Replies 33117/33119/33121 carry frames padded to 100, 152, 600 or 1536 bytes,
followed by a signed result code. This hub replies with source 0. BLE framing,
declared length and CRC are checked before decryption.

## Failure behavior

The session has bounded handshake attempts, ordered fragment assembly, duplicate
suppression and a bounded reorder window. Lost datagrams resend the same
sequence, up to five transmissions. The client never replays an application
command after reconnecting. Keepalive uses E0/E1. Missing replies, malformed
control headers and session close fail the active request. Hub login and
keepalive do not send BLE frames.

Each lock's HA lock/unlock calls are serialized. A command first obtains status,
learns type/nonce, resolves the host credential, builds the existing Vision BLE
command, then requires a parsed ACK or a subsequent status read reporting the requested
bolt state. Confirmation queries are bounded and never resend the physical
command. A
successful UDP send or relay result alone does not count as successful locking.

## Checks

Run `ruff check .`, `python tests/test_frame.py`, `python tests/test_exchange.py`
and `python tests/test_vision.py` with Home Assistant importable. The suites
need no network or physical hardware. Vision checks cover independent codec
vectors, sockaddr byte order, passthrough CRC/framing, ordered fragments,
duplicates, sequence wrap, peer checks, cancellation, packet loss and cleanup.
