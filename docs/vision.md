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

Control uses separate parsers for action replies and status replies. An
`0A22` action reply has a result/status/event layout; treating it as a full
`0A1E` status report invents battery, firmware and door fields. Successful
commands require an accepted action reply followed by a real status query
confirming the requested bolt state, with up to three queries 500 ms apart.
Delayed responses are matched by BLE command before satisfying a request.

The camera's HEVC frames decode successfully to live JPEG images. Camera and
status sessions were verified concurrently. Open-door transitions and external
keypad/app notifications remain unverified. The hub cache query returns an
empty 64-byte record on this firmware, so it cannot supply silent state updates.
The credential-list query rejects this hardware's request; commands use the
authenticated account's cloud host-credential copy. Cloud access history remains
available. Direct BLE history and guest PIN activation are not validated.

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
command, then requires an accepted action ACK and a subsequent status read reporting
the requested bolt state. Confirmation queries are bounded and never resend the physical
command. A
successful UDP send or relay result alone does not count as successful locking.

## Live video

StartLive is command 1 with five little-endian integers, `(2, 0, 0, 0, 0)`.
Response 2 reports codec and resolution; codec 5 is HEVC, not an error. The tested
hub announced 1280 × 720 but supplied 1920 × 1080 frames. StopLive is command 3,
with `(0, 0)`, and this hub responds with command 19.

Reliable channel 1 has its own sequence counter. Each video frame has a 32-byte
`<8I` header: flag, size, PTS, frame type, count, online viewers, codec, reserved.
Flags 428213528 and 428216305 carry Annex B video; frame type 1 is a keyframe.
The receiver checks frame sizes, reorders and acknowledges fragments, and keeps
a bounded queue. After overflow it waits for a keyframe. PyAV decodes in HA's
executor and encodes 960 × 540 JPEG for the camera entity's MJPEG viewer.
Video starts on demand, stops after ten idle seconds, and closes on entity unload.
No video is stored. Audio, talk and SD-card playback are not implemented.

## Checks

Run `ruff check .`, `python tests/test_frame.py`, `python tests/test_exchange.py`
`python tests/test_vision.py` and `python tests/test_camera.py` with Home Assistant importable. The suites
need no network or physical hardware. Vision checks cover independent codec
vectors, sockaddr byte order, passthrough CRC/framing, ordered fragments,
duplicates, sequence wrap, peer checks, cancellation, packet loss, interleaved
BLE replies, video assembly, JPEG decode, queue overflow and camera cleanup.
