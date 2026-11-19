"""Verified PGD898S management commands. Credential payloads stay in memory."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hmac
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES

from .api import _aes_wrap, crc8_lockly, derive_aes_key, encrypt_master_code

# PwdIdUtil: host-managed ordinary slots, excluding the one-time slots 9/49.
PIN_SLOTS = tuple(range(1, 9)) + tuple(range(10, 17)) + tuple(range(41, 49)) + tuple(range(50, 57))
NEW_PIN_SLOTS = tuple(range(41, 49))
SETTINGS = {
    "pin_genie": (1, 0x01),
    "keypad_sound": (1, 0x02),
    "auto_lock_enabled": (1, 0x08),
    "bluetooth_sound": (2, 0x02),
    "fingerprint_sound": (2, 0x20),
}
S8_THRESHOLDS = ((0, 380), (10, 421), (20, 461), (30, 488), (40, 506),
                 (50, 518), (60, 527), (70, 539), (80, 553), (90, 572))


def s8_battery_percent(raw: int) -> int:
    """Lockly Home 1.6.2 get6sAnd8sPower, verified against active app config."""
    for percent, maximum in S8_THRESHOLDS:
        if raw <= maximum:
            return percent
    return 100


class ManagementError(Exception):
    """A safe, public error; never include decrypted payloads or PINs."""


def command(mc: str, uuid: str, opcode: int, nonce: str, tail: bytes = b"", *, subtype: int | None = None) -> str:
    if len(nonce) != 16:
        raise ManagementError("A fresh lock status is required")
    enc_mc = bytes.fromhex(encrypt_master_code(mc, uuid))
    body = bytes([opcode]) + (bytes([subtype]) if subtype is not None else b"")
    body += bytes([len(enc_mc)]) + enc_mc + tail + bytes.fromhex(nonce)
    return _aes_wrap(body.hex(), derive_aes_key(mc, uuid))


def decrypt_reply(ack: str | None, mc: str, uuid: str, opcode: int, *, subtype: int | None = None) -> bytes:
    try:
        frame = bytes.fromhex(ack or "")
        header = bytes([10, opcode]) + (bytes([subtype]) if subtype is not None else b"")
        offset = 6 + len(header)
        if (frame[:4] != b"\xa1\xb2\xc3\xd4" or len(frame) < offset + 17
                or int.from_bytes(frame[4:6], "little") != len(frame)
                or frame[6:offset] != header or crc8_lockly(frame[:-1]) != frame[-1]
                or (len(frame) - offset - 1) % 16):
            raise ValueError
        return AES.new(derive_aes_key(mc, uuid), AES.MODE_ECB).decrypt(frame[offset:-1])
    except (ValueError, IndexError):
        raise ManagementError("The lock did not return a valid acknowledgement") from None


def validate_pin(pin: str) -> None:
    if not isinstance(pin, str) or not pin.isascii() or not pin.isdigit() or not 6 <= len(pin) <= 8:
        raise ManagementError("Use a PIN containing 6 to 8 digits")


def encode_name(name: str) -> bytes:
    name = name.strip()
    if not name or len(name.encode("utf-8")) > 20 or any(ord(c) < 32 for c in name):
        raise ManagementError("Enter a name of at most 20 UTF-8 bytes")
    return name.encode("utf-8").ljust(20, b"\0")


@dataclass
class Credential:
    user_type: int
    slot: int
    pin: str = field(repr=False)
    schedule: bytes = field(default=b"", repr=False)
    name: str = ""

    def public(self) -> dict:
        result = {"slot": self.slot, "name": self.name or ("Owner" if self.slot == 0 else f"PIN {self.slot}"),
                  "kind": "owner" if self.slot == 0 else "pin",
                  "editable": self.slot in PIN_SLOTS and self.user_type != 2}
        if not self.schedule or self.schedule == b"\xff" * 10:
            result["schedule"] = {"type": "always"}
        elif self.schedule[0] == 0xFE:
            result["schedule"] = {"type": "recurring", "weekdays": self.schedule[5],
                                  "start": f"{self.schedule[6]:02}:{self.schedule[7]:02}",
                                  "end": f"{self.schedule[8]:02}:{self.schedule[9]:02}"}
        else:
            result["schedule"] = {"type": "temporary", "start": decode_date(self.schedule[:5]),
                                  "end": decode_date(self.schedule[5:])}
        return result


def decode_date(data: bytes) -> str:
    try:
        return datetime(2000 + data[0], *data[1:]).isoformat(timespec="minutes")
    except (ValueError, IndexError, TypeError):
        raise ManagementError("The lock returned an unsupported credential schedule") from None


def parse_credentials(ack: str, mc: str, uuid: str) -> list[Credential]:
    data = decrypt_reply(ack, mc, uuid, 0x2D)
    entries: list[Credential] = []
    while data and any(data):
        # The lock prefixes AES padding with the number of zero bytes that follow.
        if len(data) <= 16 and data[0] == len(data) - 1 and not any(data[1:]):
            break
        if len(data) < 3:
            raise ManagementError("The credential list was truncated")
        user_type, size = data[:2]
        if not 6 <= size <= 8 or len(data) < 3 + size:
            raise ManagementError("The lock returned an unsupported credential format")
        digits = data[2:2 + size]
        if any(d > 9 for d in digits):
            raise ManagementError("The lock returned an unsupported credential format")
        slot = data[2 + size]
        end = 3 + size
        schedule, name = b"", ""
        if slot != 0 and user_type != 2:
            if len(data) < end + 30:
                raise ManagementError("The credential list was truncated")
            schedule = data[end:end + 10]
            try:
                name = data[end + 10:end + 30].split(b"\0", 1)[0].decode("utf-8")
            except UnicodeDecodeError:
                raise ManagementError("The lock returned an invalid credential name") from None
            end += 30
        entry = Credential(user_type, slot, "".join(str(d) for d in digits), schedule, name)
        entry.public()  # Validate schedules before permitting any management write.
        if any(e.slot == slot for e in entries):
            raise ManagementError("The credential list contained duplicate slots")
        entries.append(entry)
        data = data[end:]
    if not any(e.slot == 0 for e in entries):
        raise ManagementError("The owner credential is missing; no changes were made")
    return entries


def encode_schedule(options: dict, timezone: str) -> bytes:
    kind = options.get("type", "always")
    if kind == "always":
        return b"\xff" * 10
    if kind == "recurring":
        try:
            days = options["weekdays"]
            if type(days) is not int or not 1 <= days <= 127:
                raise ValueError
            start = datetime.strptime(options["start"], "%H:%M")
            end = datetime.strptime(options["end"], "%H:%M")
            if end <= start:
                raise ValueError
            return bytes([254, 0, 0, 0, 0, days, start.hour, start.minute, end.hour, end.minute])
        except (KeyError, TypeError, ValueError):
            raise ManagementError("Choose weekdays and an end time after the start time") from None
    if kind == "temporary":
        try:
            zone = ZoneInfo(timezone)
            times = [datetime.fromisoformat(options[k]) for k in ("start", "end")]
            times = [t.astimezone(zone) if t.tzinfo else t.replace(tzinfo=zone) for t in times]
            if times[1] <= times[0] or not all(2000 <= t.year <= 2099 for t in times):
                raise ValueError
            return b"".join(bytes([t.year - 2000, t.month, t.day, t.hour, t.minute]) for t in times)
        except (KeyError, TypeError, ValueError):
            raise ManagementError("Choose a valid start and end date in the lock's time zone") from None
    raise ManagementError("Unsupported schedule type")


def build_set_pin(mc: str, uuid: str, nonce: str, entry: Credential) -> str:
    validate_pin(entry.pin)
    if entry.slot not in PIN_SLOTS or len(entry.schedule) != 10:
        raise ManagementError("This credential slot cannot be changed")
    name = encode_name(entry.name)
    tail = bytes(int(d) for d in entry.pin) + bytes([entry.slot]) + entry.schedule
    tail += bytes([len(entry.name.strip().encode("utf-8"))]) + name
    return command(mc, uuid, 1, nonce, tail, subtype=0x14)


def verify_set_reply(ack: str | None, mc: str, uuid: str, entry: Credential) -> None:
    data = decrypt_reply(ack, mc, uuid, 1, subtype=0x14)
    expected = bytes(int(d) for d in entry.pin) + bytes([entry.slot]) + entry.schedule
    if not hmac.compare_digest(data[:len(expected)], expected):
        raise ManagementError("The lock did not confirm the credential change; refresh before retrying")


def build_delete_pin(mc: str, uuid: str, nonce: str, entry: Credential) -> str:
    if entry.slot not in PIN_SLOTS or entry.user_type == 2:
        raise ManagementError("This credential slot cannot be deleted")
    return command(mc, uuid, 2, nonce, bytes(int(d) for d in entry.pin) + bytes([entry.slot]), subtype=3)


class VisionManagement:
    """Serialize complete read/modify/readback transactions with bolt commands."""

    def __init__(self, coordinator) -> None:
        self.coordinator = coordinator
        self.settings: dict[str, dict[int, int]] = {}
        self.credentials: dict[str, list[dict]] = {}
        self.history: dict[str, list[dict]] = {}
        self.hub_volume: dict[str, int] = {}
        self.updated_at: dict[str, str] = {}

    def lock(self, lock_id: str) -> dict:
        lock = self.coordinator._get_lock(lock_id)
        if lock is None or self.coordinator._caps_for(lock).lock_type != 97:
            raise ManagementError("Management is currently verified for PGD898S only")
        if not self.coordinator._caps_for(lock).is_host:
            raise ManagementError("The owner account is required for access management")
        return lock

    def mutex(self, lock: dict):
        import asyncio
        return self.coordinator._vision_commands.setdefault(lock["ID"], asyncio.Lock())

    async def nonce(self, lock: dict) -> str:
        status = await self.coordinator._query_live_status(lock)
        if not status or not status.get("ble_nonce"):
            raise ManagementError("Could not obtain a fresh lock status")
        self.coordinator._learn_from_status(lock, status)
        self.coordinator._publish_status(lock, status)
        return status["ble_nonce"]

    async def exchange(self, lock: dict, opcode: int, nonce: str, tail: bytes = b"", *, subtype=None) -> str | None:
        return await self.coordinator._vision_exchange_raw(
            lock, command(str(lock["mc"]), lock["ID"], opcode, nonce, tail, subtype=subtype))

    async def read_credentials(self, lock: dict, nonce: str) -> list[Credential]:
        ack = await self.exchange(lock, 0x2D, nonce)
        entries = parse_credentials(ack, str(lock["mc"]), lock["ID"])
        self.credentials[lock["ID"]] = [e.public() for e in entries]
        return entries

    async def read_settings(self, lock: dict, nonce: str) -> dict[int, int]:
        values = {}
        for group in (1, 2):
            ack = await self.exchange(lock, 0x19, nonce, b"\x80", subtype=group)
            values[group] = decrypt_reply(ack, str(lock["mc"]), lock["ID"], 0x19, subtype=group)[0]
        self.settings[lock["ID"]] = values
        return values

    def publish(self, lock: dict) -> None:
        from datetime import timezone
        self.updated_at[lock["ID"]] = datetime.now(timezone.utc).isoformat()
        self.coordinator.async_update_listeners()

    def public(self, lock: dict) -> dict:
        lock_id = lock["ID"]
        settings = self.settings.get(lock_id, {})
        return {"lock_id": lock_id, "name": lock.get("na") or "Lockly", "timezone": lock.get("tzId") or "UTC",
                "settings": {k: bool(settings[g] & mask) for k, (g, mask) in SETTINGS.items() if g in settings},
                "credentials": self.credentials.get(lock_id, []), "history": self.history.get(lock_id, []),
                "updated_at": self.updated_at.get(lock_id), "hub_volume": self.hub_volume.get(lock_id)}

    async def async_refresh(self, lock_id: str) -> dict:
        lock = self.lock(lock_id)
        async with self.mutex(lock):
            nonce = await self.nonce(lock)
            await self.read_settings(lock, nonce)
            await self.read_credentials(lock, nonce)
            await self.read_hub_volume(lock)
            self.publish(lock)
            return self.public(lock)

    async def async_setting(self, lock_id: str, key: str, enabled: bool) -> dict:
        lock = self.lock(lock_id)
        if key not in SETTINGS or type(enabled) is not bool:
            raise ManagementError("Unsupported setting")
        async with self.mutex(lock):
            nonce = await self.nonce(lock)
            values = await self.read_settings(lock, nonce)
            group, mask = SETTINGS[key]
            wanted = values[group] | mask if enabled else values[group] & ~mask
            if wanted != values[group]:
                ack = await self.exchange(lock, 0x19, nonce, bytes([wanted]), subtype=group)
                echoed = decrypt_reply(ack, str(lock["mc"]), lock_id, 0x19, subtype=group)[0]
                actual = await self.read_settings(lock, await self.nonce(lock))
                self.publish(lock)
                if echoed != wanted or actual[group] != wanted:
                    raise ManagementError("The lock did not confirm the requested setting; refresh before retrying")
            self.publish(lock)
            return self.public(lock)

    @staticmethod
    def signature(entry: Credential) -> tuple:
        return entry.user_type, entry.slot, entry.pin, entry.schedule, entry.name

    async def async_save_pin(self, lock_id: str, name: str, pin: str, schedule: dict, slot: int | None = None) -> dict:
        lock = self.lock(lock_id)
        if pin or slot is None:
            validate_pin(pin)
        encode_name(name)
        timing = encode_schedule(schedule, lock.get("tzId") or "UTC")
        async with self.mutex(lock):
            nonce = await self.nonce(lock)
            before = await self.read_credentials(lock, nonce)
            if slot is None:
                slot = next((s for s in NEW_PIN_SLOTS if all(e.slot != s for e in before)), None)
                if slot is None:
                    raise ManagementError("All supported guest slots are occupied")
            else:
                old = next((e for e in before if e.slot == slot), None)
                if old is None or not old.public()["editable"]:
                    raise ManagementError("Select an existing editable PIN")
            if not pin:
                pin = old.pin
            if any(e.slot != slot and hmac.compare_digest(e.pin, pin) for e in before):
                raise ManagementError("Choose a PIN that is not already in use")
            desired = Credential(3, slot, pin, timing, name.strip())
            frame = build_set_pin(str(lock["mc"]), lock_id, nonce, desired)
            ack = await self.coordinator._vision_exchange_raw(lock, frame)
            # Never resend a write on a timeout: a read establishes what happened.
            after = await self.read_credentials(lock, await self.nonce(lock))
            self.publish(lock)
            self.verify_unchanged(before, after, slot)
            verify_set_reply(ack, str(lock["mc"]), lock_id, desired)
            actual = next((e for e in after if e.slot == slot), None)
            if actual is None or ((actual.pin, actual.schedule, actual.name)
                                  != (desired.pin, desired.schedule, desired.name)):
                raise ManagementError("The credential was not confirmed on the lock; refresh before retrying")
            return self.public(lock)

    @classmethod
    def verify_unchanged(cls, before: list[Credential], after: list[Credential], slot: int) -> None:
        if ({cls.signature(e) for e in before if e.slot != slot}
                != {cls.signature(e) for e in after if e.slot != slot}):
            raise ManagementError("Another credential changed during the operation; review access in Lockly Home")

    async def async_delete_pin(self, lock_id: str, slot: int) -> dict:
        lock = self.lock(lock_id)
        async with self.mutex(lock):
            nonce = await self.nonce(lock)
            before = await self.read_credentials(lock, nonce)
            old = next((e for e in before if e.slot == slot), None)
            if old is None:
                raise ManagementError("That credential no longer exists")
            frame = build_delete_pin(str(lock["mc"]), lock_id, nonce, old)
            ack = await self.coordinator._vision_exchange_raw(lock, frame)
            after = await self.read_credentials(lock, await self.nonce(lock))
            self.publish(lock)
            self.verify_unchanged(before, after, slot)
            if decrypt_reply(ack, str(lock["mc"]), lock_id, 2)[:2] != b"\x03\x00" or any(e.slot == slot for e in after):
                raise ManagementError("Deletion was not confirmed on the lock; refresh before retrying")
            return self.public(lock)

    async def async_history(self, lock_id: str) -> list[dict]:
        from .api import build_query_log_cmd, parse_log_ack
        lock = self.lock(lock_id)
        async with self.mutex(lock):
            nonce = await self.nonce(lock)
            caps = self.coordinator._caps_for(lock)
            ack = await self.coordinator._vision_exchange_raw(
                lock, build_query_log_cmd(str(lock["mc"]), lock_id, nonce, caps=caps))
            decrypt_reply(ack, str(lock["mc"]), lock_id, 0x78)
            records = parse_log_ack(ack, str(lock["mc"]), lock_id, caps=caps, timezone_name=lock.get("tzId"))
            if records is None:
                raise ManagementError("Could not read access history")
            from .api import describe_open_type
            for record in records:
                record["event_type"] = describe_open_type(record["co"])
            self.history[lock_id] = sorted(records, key=lambda r: r["tm"], reverse=True)[:120]
            self.publish(lock)
            return records


    async def read_hub_volume(self, lock: dict) -> int:
        import struct
        from .vision import VisionError
        try:
            data = await self.coordinator._vision_client(lock).async_hub_request(33048, struct.pack("<I", 0), {33049})
            value = struct.unpack_from("<i", data)[0]
            if value not in (0, 1, 2):
                raise ValueError
        except (VisionError, OSError, ValueError, struct.error):
            raise ManagementError("Could not read the hub doorbell volume") from None
        self.hub_volume[lock["ID"]] = value
        return value

    async def async_hub_volume(self, lock_id: str, value: int) -> dict:
        import struct
        from .vision import VisionError
        lock = self.lock(lock_id)
        if type(value) is not int or value not in (0, 1, 2):
            raise ManagementError("Choose Mute, Low or High")
        async with self.mutex(lock):
            if await self.read_hub_volume(lock) != value:
                try:
                    data = await self.coordinator._vision_client(lock).async_hub_request(
                        33050, struct.pack("<2i", value, 0), {33051})
                    if len(data) < 4 or struct.unpack_from("<i", data)[0] != 0:
                        raise ValueError
                except (VisionError, OSError, ValueError, struct.error):
                    raise ManagementError(
                        "The hub did not confirm the volume change; refresh before retrying") from None
                if await self.read_hub_volume(lock) != value:
                    raise ManagementError("The hub volume did not match the requested setting")
            self.publish(lock)
            return self.public(lock)
