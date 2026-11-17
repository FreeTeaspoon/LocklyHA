"""Offline Vision transport checks. No sockets, hubs or real credentials."""
import asyncio
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from custom_components.lockly import LocklyCoordinator
from custom_components.lockly.api import crc8_lockly
from custom_components.lockly.capabilities import resolve_capabilities
from custom_components.lockly.vision import (
    VisionClient, VisionError, decode_packet, encode_packet, is_vision_lock,
    pack_address, pack_control, pack_uid, unpack_address, unpack_bypass,
)

UID = "LOCKLYV-000001-ABCDE"
PEER = ("192.0.2.10", 32108)


def ble_frame():
    body = b"\xa1\xb2\xc3\xd4" + struct.pack("<H", 41) + b"\x00\xa1" + bytes(range(32))
    return body + bytes([crc8_lockly(body)])


def bypass(frame=None, padding=600, result=0):
    frame = frame or ble_frame()
    return struct.pack("<4I", 0, 0, 0, len(frame)) + frame.ljust(padding, b"\0") + struct.pack("<i", result)


def wire(kind, payload=b""):
    return encode_packet(struct.pack("!BBH", 0xF1, kind, len(payload)) + payload)


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.closed = False
        self.protocol = None

    def sendto(self, packet, address):
        self.sent.append((decode_packet(packet), address))

    def close(self):
        self.closed = True
        if self.protocol:
            asyncio.get_running_loop().call_soon(self.protocol.connection_lost, None)


class CodecTests(unittest.TestCase):
    def test_native_sdk_vectors(self):
        # Independently obtained by calling Lockly Home 1.6.2's SDK offline.
        self.assertEqual(encode_packet(bytes.fromhex("f1300000")).hex(), "98f2c1d6")
        plain = bytes.fromhex("f14100144c4f434b4c59560000000001414243444500000000")
        expected = bytes.fromhex("98835339c36ee64768ef80305c32b1eaa6a0fbef9357e0ec5d")
        self.assertEqual(encode_packet(plain), expected)
        self.assertEqual(decode_packet(expected), plain)

    def test_all_byte_values(self):
        value = bytes(range(256)) * 4
        self.assertEqual(decode_packet(encode_packet(value)), value)
        self.assertEqual(encode_packet(b""), b"")

    def test_uid(self):
        self.assertEqual(pack_uid(UID), b"LOCKLYV\0\0\0\0\1ABCDE\0\0\0")
        for invalid in ["", "OTHER-1-ABCDE", "LOCKLYV-4294967296-ABCDE", "LOCKLYV-1-too-long-suffix"]:
            with self.subTest(value=invalid), self.assertRaises(VisionError):
                pack_uid(invalid)

    def test_sdk_address_byte_order(self):
        expected = bytes.fromhex("0002dc3ab432a8c00000000000000000")
        self.assertEqual(pack_address(("192.168.50.180", 15068)), expected)
        self.assertEqual(unpack_address(expected), ("192.168.50.180", 15068))
        with self.assertRaises(VisionError):
            unpack_address(pack_address(("127.0.0.1", 1234)))

    def test_medium_and_short_passthrough_from_hub(self):
        # Hardware replies have source=0, not the outgoing app's source=2.
        self.assertEqual(unpack_bypass(bypass()), ble_frame())
        self.assertEqual(unpack_bypass(bypass(padding=100)), ble_frame())

    def test_bad_passthrough_and_ble_crc(self):
        for payload in [bypass(result=-1), bypass()[:-1], bypass(frame=ble_frame()[:-1] + b"\x00")]:
            with self.subTest(size=len(payload)), self.assertRaises(VisionError):
                unpack_bypass(payload)
        malformed = bytearray(bypass())
        struct.pack_into("<I", malformed, 12, 601)
        with self.assertRaises(VisionError):
            unpack_bypass(malformed)

    def test_vision_is_not_wifi_native(self):
        lock = {"p2pdid": UID, "p2ppw": "test-password", "hubid": ""}
        self.assertTrue(is_vision_lock(lock))
        self.assertFalse(LocklyCoordinator._mqtt_only(lock))
        self.assertTrue(LocklyCoordinator._mqtt_only({"hubid": ""}))
        self.assertFalse(is_vision_lock({"hubid": "PGH220-test"}))


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.frames = []
        self.client = VisionClient(UID, "test-password", self.frames.append)
        self.transport = FakeTransport()
        self.transport.protocol = self.client
        self.client.connection_made(self.transport)
        self.client._peer = PEER
        self.client._authenticated = True

    async def asyncTearDown(self):
        await self.client.async_close()

    def deliver(self, sequence, data, address=PEER):
        self.client.datagram_received(wire(0xD0, b"\xd1\0" + struct.pack("!H", sequence) + data), address)

    async def test_duplicate_replies_and_out_of_order_fragments(self):
        message = pack_control(33121, bypass())
        self.deliver(1, message[100:])
        self.assertEqual(self.frames, [])
        self.deliver(0, message[:100])
        self.deliver(1, message[100:])
        self.assertEqual(self.frames, [ble_frame()])
        self.assertEqual(len(self.transport.sent), 3)  # Every duplicate is ACKed.

    async def test_sequence_wrap(self):
        self.client._rx_sequence = 65535
        message = pack_control(33121, bypass())
        self.deliver(0, message[50:])
        self.deliver(65535, message[:50])
        self.assertEqual(self.frames, [ble_frame()])
        self.assertEqual(self.client._rx_sequence, 1)

    async def test_foreign_peer_and_invalid_packet_are_ignored(self):
        self.deliver(0, pack_control(33121, bypass()), ("192.0.2.11", 32108))
        self.client.datagram_received(wire(0xD0, b"\xd1"), PEER)
        self.client.datagram_received(b"\x00\x01\x02\x03", PEER)
        self.assertEqual(self.frames, [])
        self.assertTrue(self.client.connected)

    async def test_ack_removes_only_named_sequences(self):
        self.client._pending = {0: (b"", 0, 1), 1: (b"", 0, 1)}
        self.client.datagram_received(wire(0xD1, b"\xd1\0\0\1\0\1"), PEER)
        self.assertEqual(set(self.client._pending), {0})

    async def test_reorder_window_is_bounded(self):
        for n in range(128, 300):
            self.deliver(n, b"test")
        self.assertEqual(self.client._chunks, {})

    async def test_malformed_control_closes_session(self):
        self.deliver(0, bytes(24))
        self.assertFalse(self.client.connected)
        self.assertTrue(self.transport.closed)

    async def test_login_punch_requires_expected_target_and_uid(self):
        self.client._peer = None
        self.client._authenticated = False
        self.client._targets.add(PEER)
        self.client._ready = asyncio.get_running_loop().create_future()
        self.client.datagram_received(wire(0x42, pack_uid(UID)), ("192.0.2.11", 32108))
        self.assertFalse(self.client._ready.done())
        self.client.datagram_received(wire(0x42, pack_uid(UID)), PEER)
        self.assertTrue(self.client._ready.done())
        self.assertEqual(self.client._peer, PEER)

    async def test_rpc_cancellation_does_not_replay_command(self):
        self.client._connect = AsyncMock()
        request = asyncio.create_task(self.client.async_exchange(ble_frame()))
        await asyncio.sleep(0)
        self.assertEqual(len(self.transport.sent), 1)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.assertFalse(self.client.connected)
        self.assertEqual(len(self.transport.sent), 1)

    async def test_command_response_uses_hardware_frame(self):
        self.client._connect = AsyncMock()
        request = asyncio.create_task(self.client.async_exchange(ble_frame()))
        await asyncio.sleep(0)
        self.deliver(0, pack_control(33121, bypass()))
        self.assertEqual(await request, ble_frame())
        self.assertEqual(self.frames, [])  # Explicit reply isn't pushed twice.

    async def test_failed_command_has_no_fallback_or_replay(self):
        self.client._connect = AsyncMock()
        request = asyncio.create_task(self.client.async_exchange(ble_frame()))
        await asyncio.sleep(0)
        self.deliver(0, pack_control(33121, bypass(result=-4)))
        with self.assertRaises(VisionError):
            await request
        self.assertEqual(len([x for x in self.transport.sent if x[0][1] == 0xD0]), 1)

    async def test_packet_loss_retransmits_same_sequence_then_stops_after_ack(self):
        self.client._last_received = time.monotonic()
        data = b"\xd1\0\0\x07request"
        self.client._pending[7] = (data, time.monotonic() - 1, 1)
        self.client._maintenance = asyncio.create_task(self.client._maintain())
        await asyncio.sleep(0.3)
        sent = [packet[4:] for packet, _ in self.transport.sent if packet[1] == 0xD0]
        self.assertEqual(sent, [data])
        self.assertEqual(self.client._pending[7][2], 2)
        self.client.datagram_received(wire(0xD1, b"\xd1\0\0\1\0\x07"), PEER)
        await asyncio.sleep(0.8)
        sent = [packet[4:] for packet, _ in self.transport.sent if packet[1] == 0xD0]
        self.assertEqual(sent, [data])
        self.assertFalse(self.client._pending)

    async def test_packet_loss_exhaustion_closes_without_new_request(self):
        self.client._last_received = time.monotonic()
        self.client._pending[7] = (b"request", time.monotonic() - 1, 5)
        self.client._maintenance = asyncio.create_task(self.client._maintain())
        await asyncio.sleep(0.3)
        self.assertFalse(self.client.connected)
        self.assertFalse(any(packet[1] == 0xD0 for packet, _ in self.transport.sent))

    async def test_close_without_maintenance_waits_for_old_socket(self):
        await asyncio.wait_for(self.client.async_close(), 1)
        self.assertTrue(self.transport.closed)
        self.assertTrue(self.client._lost.done())

    async def test_endpoint_creation_failure_can_close_and_retry(self):
        await self.client._disconnect()
        loop = asyncio.get_running_loop()
        address = [(2, 2, 17, "", ("192.0.2.1", 32100))]
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=address)), \
             patch.object(loop, "run_in_executor", AsyncMock(return_value="192.0.2.2")), \
             patch.object(loop, "create_datagram_endpoint", AsyncMock(side_effect=OSError("no socket"))):
            for _ in range(2):
                with self.assertRaises(OSError):
                    await asyncio.wait_for(self.client.async_connect(), 1)
            await asyncio.wait_for(self.client.async_close(), 1)
        self.assertIsNone(self.client._ready)

    async def test_connect_only_sends_no_ble_frame(self):
        self.client._connect = AsyncMock()
        await self.client.async_connect()
        self.client._connect.assert_awaited_once()
        self.assertEqual(self.transport.sent, [])


class CoordinatorCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_cloud_credential_fallback_requires_hardware_state(self):
        lock = {"ID": "aa0000000000000000000001", "mc": "12345678", "hc": "123456",
                "mod": "PGD898S", "p2pdid": UID, "p2ppw": "test-password"}
        caps = resolve_capabilities(lock)
        self.assertEqual(caps.lock_type, 97)
        self.assertTrue(caps.is_vision)
        self.assertTrue(caps.supports_timestamp)
        self.assertEqual(caps.encrypt_type, 11)
        for unlock in (False, True):
            for reported in (False, True, None):
                with self.subTest(unlock=unlock, reported=reported):
                    coordinator = SimpleNamespace(
                        _query_live_status=AsyncMock(return_value={"is_locked": reported}),
                        _learn_from_status=lambda *args: None,
                        _publish_status=lambda *args: None,
                        _nonces={}, _host_passwords={},
                        _caps_for=lambda _: caps,
                        _vision_exchange_raw=AsyncMock(side_effect=["pwd-reply", "command-reply"]),
                    )
                    ack = {"is_locked": reported} if reported is not None else {}
                    with patch("custom_components.lockly.asyncio.sleep", AsyncMock()), \
                         patch("custom_components.lockly.parse_pwd_list_ack", return_value=None), \
                         patch("custom_components.lockly.parse_ack", return_value=ack), \
                         patch("custom_components.lockly.build_lock_cmd", return_value="lock-frame") as lock_cmd, \
                         patch("custom_components.lockly.build_unlock_cmd", return_value="unlock-frame") as unlock_cmd:
                        accepted = await LocklyCoordinator._send_vision_command(coordinator, lock, unlock=unlock)
                        self.assertEqual(accepted, reported is (not unlock))
                        selected = unlock_cmd if unlock else lock_cmd
                        self.assertEqual(selected.call_args.args[2], lock["hc"])
                        self.assertEqual(coordinator._vision_exchange_raw.await_count, 2)

    async def test_motor_completion_is_confirmed_without_replaying_command(self):
        lock = {"ID": "aa0000000000000000000001", "mc": "12345678", "hc": "123456",
                "mod": "PGD898S", "p2pdid": UID, "p2ppw": "test-password"}
        for unlock in (False, True):
            for readings, success, queries in [
                ([{"is_locked": unlock}, {"is_locked": not unlock}], True, 3),
                ([None, {"is_locked": not unlock}], True, 3),
                ([None, None, None], False, 4),
                ([{"is_locked": unlock}] * 3, False, 4),
            ]:
                with self.subTest(unlock=unlock, success=success, readings=readings):
                    published = []
                    coordinator = SimpleNamespace(
                        _query_live_status=AsyncMock(side_effect=[{"is_locked": unlock}, *readings]),
                        _learn_from_status=lambda *args: None,
                        _publish_status=lambda _, status: published.append(status),
                        _nonces={}, _host_passwords={lock["ID"]: "123456"},
                        _caps_for=lambda _: resolve_capabilities(lock),
                        _vision_exchange_raw=AsyncMock(return_value="command-reply"),
                    )
                    with patch("custom_components.lockly.asyncio.sleep", AsyncMock()), \
                         patch("custom_components.lockly.parse_ack", return_value={"is_locked": unlock}):
                        accepted = await LocklyCoordinator._send_vision_command(coordinator, lock, unlock=unlock)
                    self.assertEqual(accepted, success)
                    self.assertEqual(coordinator._vision_exchange_raw.await_count, 1)
                    self.assertEqual(coordinator._query_live_status.await_count, queries)
                    self.assertEqual(published[-1]["is_locked"], not unlock if success else unlock)

    async def test_no_status_prevents_actuation(self):
        coordinator = SimpleNamespace(_query_live_status=AsyncMock(return_value=None))
        self.assertFalse(await LocklyCoordinator._send_vision_command(coordinator, {}, unlock=True))


if __name__ == "__main__":
    unittest.main()
