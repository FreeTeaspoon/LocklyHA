"""Offline credential safety, protocol validation and transaction checks."""
import asyncio
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from Crypto.Cipher import AES

from custom_components.lockly.api import crc8_lockly, derive_aes_key
from custom_components.lockly.vision_features import (
    Credential, ManagementError, VisionManagement, build_delete_pin, build_set_pin,
    decrypt_reply, encode_schedule, parse_credentials, s8_battery_percent, verify_set_reply,
)
from custom_components.lockly.capabilities import LockCapabilities

MC, UUID, NONCE = "12345678", "0123456789abcdef01234567", "0102030405060708"
OWNER = Credential(2, 0, "1234567")
GUEST = Credential(3, 7, "923456", b"\xff" * 10, "Family")


def reply(opcode, plain, subtype=None):
    # Firmware's padding marker is the number of following zero bytes.
    count = (15 - len(plain) % 16) % 16
    plain += bytes([count]) + b"\0" * count
    header = bytes([10, opcode]) + (bytes([subtype]) if subtype is not None else b"")
    encrypted = AES.new(derive_aes_key(MC, UUID), AES.MODE_ECB).encrypt(plain)
    body = b"\xa1\xb2\xc3\xd4" + (7 + len(header) + len(encrypted)).to_bytes(2, "little") + header + encrypted
    return (body + bytes([crc8_lockly(body)])).hex()


def record(entry):
    body = bytes([entry.user_type, len(entry.pin)]) + bytes(int(d) for d in entry.pin) + bytes([entry.slot])
    if entry.slot and entry.user_type != 2:
        body += entry.schedule + entry.name.encode().ljust(20, b"\0")
    return body


class ProtocolTests(unittest.TestCase):
    def test_named_credentials_owner_and_schedule(self):
        ack = reply(0x2D, record(OWNER) + record(GUEST))
        entries = parse_credentials(ack, MC, UUID)
        self.assertEqual(entries, [OWNER, GUEST])
        self.assertFalse(entries[0].public()["editable"])
        self.assertEqual(entries[1].public()["schedule"], {"type": "always"})
        public = json.dumps([e.public() for e in entries])
        self.assertNotIn(GUEST.pin, public)
        self.assertNotIn(OWNER.pin, repr(entries))

    def test_reject_incomplete_list_and_duplicates(self):
        for payload in (record(OWNER) + record(GUEST)[:10], record(OWNER) * 2,
                        record(GUEST), record(OWNER) + b"\x03\xff"):
            with self.subTest(length=len(payload)), self.assertRaises(ManagementError):
                parse_credentials(reply(0x2D, payload), MC, UUID)

    def test_reject_crc_length_opcode_and_subtype(self):
        valid = bytes.fromhex(reply(0x19, b"\x22", 2))
        for damaged in (valid[:-1], valid[:-1] + bytes([valid[-1] ^ 1]),
                        valid[:4] + b"\0\0" + valid[6:]):
            with self.assertRaises(ManagementError):
                decrypt_reply(damaged.hex(), MC, UUID, 0x19, subtype=2)
        with self.assertRaises(ManagementError):
            decrypt_reply(valid.hex(), MC, UUID, 0x19, subtype=1)
        with self.assertRaises(ManagementError):
            decrypt_reply(valid.hex(), MC, UUID, 0x2D)

    def test_host_and_special_slots_protected(self):
        for slot in (0, 9, 49, 69, 109, 255):
            entry = Credential(3, slot, "923456", b"\xff" * 10, "Test")
            with self.subTest(slot=slot):
                with self.assertRaises(ManagementError):
                    build_set_pin(MC, UUID, NONCE, entry)
                with self.assertRaises(ManagementError):
                    build_delete_pin(MC, UUID, NONCE, entry)

    def test_write_frame_has_name_schedule_and_nonce(self):
        frame = bytes.fromhex(build_set_pin(MC, UUID, NONCE, GUEST))
        plain = AES.new(derive_aes_key(MC, UUID), AES.MODE_ECB).decrypt(frame[6:-2])
        self.assertEqual(plain[:2], b"\x01\x14")
        self.assertIn(bytes([7]) + b"\xff" * 10 + bytes([6]) + b"Family" + b"\0" * 14, plain)
        self.assertIn(bytes.fromhex(NONCE), plain)
        self.assertEqual(frame[-2] & 15, 5)

    def test_echo_must_match_pin_slot_and_schedule(self):
        expected = bytes(int(d) for d in GUEST.pin) + bytes([GUEST.slot]) + GUEST.schedule
        verify_set_reply(reply(1, expected, 0x14), MC, UUID, GUEST)
        for index in (0, len(GUEST.pin), len(GUEST.pin) + 1):
            modified = bytearray(expected)
            modified[index] ^= 1
            with self.assertRaises(ManagementError):
                verify_set_reply(reply(1, bytes(modified), 0x14), MC, UUID, GUEST)

    def test_schedule_timezone_and_recurring(self):
        schedule = encode_schedule({"type": "temporary", "start": "2026-11-20T01:00:00+00:00",
                                    "end": "2026-11-20T02:00:00+00:00"}, "Asia/Hong_Kong")
        self.assertEqual(schedule, bytes([26, 11, 20, 9, 0, 26, 11, 20, 10, 0]))
        recurring = encode_schedule({"type": "recurring", "weekdays": 65, "start": "09:30", "end": "17:45"}, "UTC")
        self.assertEqual(recurring, bytes([254, 0, 0, 0, 0, 65, 9, 30, 17, 45]))
        self.assertEqual(Credential(3, 7, "923456", recurring, "Test").public()["schedule"]["weekdays"], 65)
        for options in ({"type": "temporary", "start": "bad", "end": "bad"},
                        {"type": "recurring", "weekdays": 0, "start": "09:00", "end": "17:00"},
                        {"type": "recurring", "weekdays": 1, "start": "17:00", "end": "09:00"}):
            with self.assertRaises(ManagementError):
                encode_schedule(options, "UTC")

    def test_app_battery_boundaries_and_legacy_error(self):
        self.assertEqual(s8_battery_percent(478), 30)  # generic linear curve incorrectly gave 19
        self.assertEqual(s8_battery_percent(510), 50)
        self.assertEqual(s8_battery_percent(527), 60)
        self.assertEqual(s8_battery_percent(528), 70)
        self.assertEqual(s8_battery_percent(380), 0)
        self.assertEqual(s8_battery_percent(650), 100)

    def test_battery_flag_is_not_a_percentage_and_reported_value_wins(self):
        from custom_components.lockly.sensor import LocklyBatterySensor
        sensor = LocklyBatterySensor.__new__(LocklyBatterySensor)
        sensor._lock_id = UUID
        values = {"ID": UUID, "wakeup_voltage": 510}
        sensor.coordinator = SimpleNamespace(data={UUID: values}, _caps_for=lambda _: LockCapabilities(lock_type=97))
        self.assertEqual(sensor.native_value, 50)
        self.assertTrue(sensor.extra_state_attributes["estimated"])
        values["battery_percent"] = 60
        self.assertEqual(sensor.native_value, 60)
        del values["battery_percent"]
        del values["wakeup_voltage"]
        for low in (False, True):
            values["low_battery"] = low
            self.assertIsNone(sensor.native_value)
            self.assertEqual(sensor.extra_state_attributes["low_battery"], low)

    def test_history_uses_lock_timezone(self):
        from custom_components.lockly.api import parse_log_ack
        stamp = bytes([26, 11, 20, 9, 0, 0])
        ack = reply(0x78, b"\0" + stamp + bytes([17, 7, 0, 42, 0]))
        records = parse_log_ack(ack, MC, UUID, LockCapabilities(lock_type=97), "Asia/Hong_Kong")
        self.assertEqual(records[0]["tm"], int(datetime(2026, 11, 20, 1, tzinfo=timezone.utc).timestamp() * 1000))
        self.assertEqual(records[0]["pid"], 7)
        self.assertEqual(records[0]["id"], 42)
        no_user = reply(0x78, b"\0" + stamp + bytes([1, 255, 0, 43, 0]))
        records = parse_log_ack(no_user, MC, UUID, LockCapabilities(lock_type=97), "Asia/Hong_Kong")
        self.assertIsNone(records[0]["pid"])


class TransactionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.lock = {"ID": UUID, "mc": MC, "mod": "PGD898S", "tzId": "Asia/Hong_Kong"}
        self.coordinator = SimpleNamespace(_vision_commands={},
            _get_lock=lambda _: self.lock, _caps_for=lambda _: LockCapabilities(lock_type=97),
            _vision_exchange_raw=AsyncMock(), async_update_listeners=lambda: None)
        self.manager = VisionManagement(self.coordinator)
        self.manager.nonce = AsyncMock(return_value=NONCE)

    async def test_setting_preserves_unknown_bits_and_verifies(self):
        self.manager.read_settings = AsyncMock(side_effect=[{1: 0xDA, 2: 0x22}, {1: 0xD8, 2: 0x22}])
        self.manager.exchange = AsyncMock(return_value=reply(0x19, b"\xd8", 1))
        await self.manager.async_setting(UUID, "keypad_sound", False)
        self.assertEqual(self.manager.exchange.await_args.args[3], b"\xd8")
        self.assertEqual(self.manager.read_settings.await_count, 2)

    async def test_failed_setting_readback_does_not_retry_write(self):
        self.manager.read_settings = AsyncMock(side_effect=[{1: 2, 2: 0}, {1: 2, 2: 0}])
        self.manager.exchange = AsyncMock(return_value=reply(0x19, b"\0", 1))
        with self.assertRaises(ManagementError):
            await self.manager.async_setting(UUID, "keypad_sound", False)
        self.assertEqual(self.manager.exchange.await_count, 1)

    async def test_duplicate_pin_prevents_write(self):
        self.manager.read_credentials = AsyncMock(return_value=[OWNER, GUEST])
        with self.assertRaises(ManagementError):
            await self.manager.async_save_pin(UUID, "Test", GUEST.pin, {"type": "always"})
        self.coordinator._vision_exchange_raw.assert_not_awaited()

    async def test_delete_owner_never_writes(self):
        self.manager.read_credentials = AsyncMock(return_value=[OWNER, GUEST])
        with self.assertRaises(ManagementError):
            await self.manager.async_delete_pin(UUID, 0)
        self.coordinator._vision_exchange_raw.assert_not_awaited()

    async def test_edit_keeps_pin_and_preserves_other_users(self):
        edited = Credential(3, 7, GUEST.pin, GUEST.schedule, "Renamed")
        self.manager.read_credentials = AsyncMock(side_effect=[[OWNER, GUEST], [OWNER, edited]])
        echoed = bytes(int(d) for d in GUEST.pin) + b"\x07" + GUEST.schedule
        self.coordinator._vision_exchange_raw.return_value = reply(1, echoed, 0x14)
        await self.manager.async_save_pin(UUID, "Renamed", "", {"type": "always"}, 7, self.manager.revision(GUEST))
        self.assertEqual(self.coordinator._vision_exchange_raw.await_count, 1)

    async def test_stale_card_cannot_modify_a_reused_slot(self):
        self.manager.read_credentials = AsyncMock(return_value=[OWNER, GUEST])
        for token in (None, "stale", self.manager.revision(Credential(3, 7, "783892", GUEST.schedule, "Old"))):
            with self.assertRaises(ManagementError):
                await self.manager.async_delete_pin(UUID, 7, token)
            with self.assertRaises(ManagementError):
                await self.manager.async_save_pin(UUID, "Test", "", {"type": "always"}, 7, token)
        self.coordinator._vision_exchange_raw.assert_not_awaited()

    def test_revision_does_not_reveal_a_pin_and_changes_after_restart(self):
        token = self.manager.revision(GUEST)
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.assertNotEqual(token, VisionManagement(self.coordinator).revision(GUEST))

    async def test_uncertain_write_reads_but_never_replays(self):
        self.manager.read_credentials = AsyncMock(side_effect=[[OWNER, GUEST], [OWNER, GUEST]])
        self.coordinator._vision_exchange_raw.return_value = None
        with self.assertRaises(ManagementError):
            await self.manager.async_save_pin(UUID, "Test", "783892", {"type": "always"})
        self.assertEqual(self.coordinator._vision_exchange_raw.await_count, 1)
        self.assertEqual(self.manager.read_credentials.await_count, 2)

    def test_concurrent_existing_user_change_is_detected(self):
        with self.assertRaises(ManagementError):
            self.manager.verify_unchanged([OWNER, GUEST], [OWNER], 41)

    async def test_bolt_and_management_share_mutex(self):
        self.coordinator._vision_commands[UUID] = asyncio.Lock()
        self.assertIs(self.manager.mutex(self.lock), self.coordinator._vision_commands[UUID])


class AuthorizationTests(unittest.IsolatedAsyncioTestCase):
    def test_non_admin_cannot_even_schedule_access_request(self):
        from homeassistant.exceptions import Unauthorized
        from custom_components.lockly.management import websocket_management
        hass = SimpleNamespace(async_create_background_task=Mock())
        for user in (None, SimpleNamespace(is_admin=False)):
            connection = SimpleNamespace(user=user)
            with self.assertRaises(Unauthorized):
                websocket_management(hass, connection, {"id": 1, "type": "lockly/management", "action": "get"})
        hass.async_create_background_task.assert_not_called()

    async def test_public_websocket_response_cannot_contain_pins(self):
        from custom_components.lockly.management import websocket_management
        manager = SimpleNamespace(coordinator=SimpleNamespace(locks=[{"ID": UUID}]),
                                  lock=lambda _: {"ID": UUID}, public=lambda _: {"credentials": [GUEST.public()]})
        hass = SimpleNamespace(data={"lockly": {"entry": SimpleNamespace(management=manager)}})
        connection = SimpleNamespace(send_result=Mock(), send_error=Mock())
        # Test the actual async handler beneath HA's admin/task decorators.
        handler = websocket_management.__wrapped__.__wrapped__
        await handler(hass, connection, {"id": 1, "lock_id": UUID, "action": "get"})
        encoded = json.dumps(connection.send_result.call_args.args[1])
        self.assertNotIn(GUEST.pin, encoded)
        self.assertNotIn("pin", connection.send_result.call_args.args[1]["credentials"][0])
        connection.send_error.assert_not_called()


class HubTests(unittest.IsolatedAsyncioTestCase):
    async def test_volume_readback_and_failure(self):
        import struct
        lock = {"ID": UUID}
        client = SimpleNamespace(async_hub_request=AsyncMock(side_effect=[
            struct.pack("<2i", 2, 0), struct.pack("<2i", 0, 0), struct.pack("<2i", 1, 0)]))
        coordinator = SimpleNamespace(_get_lock=lambda _: lock,
            _caps_for=lambda _: LockCapabilities(lock_type=97), _vision_client=lambda _: client,
            _vision_commands={}, async_update_listeners=lambda: None)
        manager = VisionManagement(coordinator)
        result = await manager.async_hub_volume(UUID, 1)
        self.assertEqual(result["hub_volume"], 1)
        self.assertEqual(client.async_hub_request.await_args_list[1].args[:2], (33050, struct.pack("<2i", 1, 0)))
        client.async_hub_request = AsyncMock(side_effect=[struct.pack("<2i", 1, 0),
            struct.pack("<2i", 0, 0), struct.pack("<2i", 1, 0)])
        with self.assertRaises(ManagementError):
            await manager.async_hub_volume(UUID, 2)
        self.assertEqual(client.async_hub_request.await_count, 3)


if __name__ == "__main__":
    unittest.main()
