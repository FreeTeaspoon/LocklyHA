"""Private fingerprint and account access workflows for Vision owners."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time

import aiohttp

from .api import AccountManagementError, api_get_devices, api_management_request, des3_decrypt
from .vision_sharing import SharingMixin
from .vision import VisionError
from .vision_features import ManagementError, decrypt_reply, encode_name


def parse_fingerprints(data: bytes) -> list[dict]:
    """15 reports capacity, followed by occupied slots; capacity is not a count."""
    if len(data) < 3 or data[0] != 1 or not 1 <= data[1] <= 127:
        raise ManagementError("Unsupported fingerprint list")
    # Strip the same marker/zero AES padding as other model-97 commands.
    end = len(data)
    while end > 2 and data[end - 1] == 0:
        end -= 1
    if end > 2 and data[end - 1] == len(data) - end:
        end -= 1
    values = data[2:end]
    # Some firmware uses zero-only padding. Occupied IDs must be unique and
    # within the advertised capacity; never infer the maximum ID from padding.
    entries = [{"slot": value & 127, "delegated": bool(value & 128)} for value in values if value]
    if any(not 1 <= e["slot"] <= data[1] for e in entries) or len({e["slot"] for e in entries}) != len(entries):
        raise ManagementError("Ambiguous fingerprint list; no changes were made")
    return entries


class VisionAccess(SharingMixin):
    def __init__(self, manager) -> None:
        self.manager = manager
        self.fingerprints: dict[str, list[dict]] = {}
        self.cloud_fingers: dict[str, list[dict]] = {}
        self.shares: dict[str, list[dict]] = {}
        self.raw_shares: dict[str, list[dict]] = {}
        self.enrollment: dict[str, dict] = {}
        self._timers: dict[str, asyncio.Task] = {}

    async def cloud(self, endpoint: str, request: dict) -> dict:
        c = self.manager.coordinator
        try:
            return await api_management_request(c._session, c.jwt, c.des3_key, endpoint, request)
        except AccountManagementError as exc:
            raise ManagementError(str(exc)) from None
        except (ValueError, OSError, TimeoutError, aiohttp.ClientError):
            raise ManagementError("Lockly did not confirm the account operation. Refresh before retrying") from None

    def revision(self, entry: dict) -> str:
        return hmac.new(
            self.manager._revision_key, json.dumps(entry, sort_keys=True).encode(), hashlib.sha256
        ).hexdigest()

    async def read_directory(self, lock: dict) -> list[dict]:
        """Read fresh account metadata before modifying a single PIN profile."""
        c = self.manager.coordinator
        locks, key = await api_get_devices(c._session, c.jwt, c.email)
        current = next((entry for entry in locks if entry.get("ID") == lock["ID"]), None)
        rows = current.get("usrarr") if current else None
        if key is None or not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ManagementError("Could not read the account directory. No eKey was created")
        c.des3_key = key
        return rows

    async def read_fingers(self, lock: dict, nonce: str) -> list[dict]:
        ack = await self.manager.exchange(lock, 0x15, nonce, b"\x01")
        entries = parse_fingerprints(decrypt_reply(ack, str(lock["mc"]), lock["ID"], 0x15))
        response = await self.cloud("getFingerprintList", {"dv": lock["ID"], "isHost": True, "staffNo": ""})
        try:
            raw = json.loads(des3_decrypt(self.manager.coordinator.des3_key, response["usrarr"]))["usrarr"]
            if not isinstance(raw, list):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ManagementError("Could not read fingerprint names from Lockly") from None
        self.cloud_fingers[lock["ID"]] = raw
        for entry in entries:
            cloud = next((e for e in raw if e.get("pid") == entry["slot"] and e.get("dutype") == "F"), {})
            entry["name"] = cloud.get("fn") or f"Fingerprint {entry['slot']}"
            entry["name_source"] = "lockly_account" if cloud else "slot"
            entry["revision"] = self.revision({**entry, "cloud": cloud})
        self.fingerprints[lock["ID"]] = entries
        return entries

    async def refresh_fingers(self, lock_id: str) -> dict:
        lock = self.manager.lock(lock_id)
        async with self.manager.mutex(lock):
            await self.read_fingers(lock, await self.manager.nonce(lock))
            self.manager.publish(lock)
        return self.manager.public(lock)

    async def change_finger(self, lock_id: str, slot: int, revision: str, name: str | None = None) -> dict:
        lock = self.manager.lock(lock_id)
        if name is not None:
            encode_name(name)
        async with self.manager.mutex(lock):
            nonce = await self.manager.nonce(lock)
            before = await self.read_fingers(lock, nonce)
            old = next((e for e in before if e["slot"] == slot), None)
            if old is None or not revision or not hmac.compare_digest(old["revision"], revision):
                raise ManagementError("This fingerprint changed. Refresh before changing it")
            if old["delegated"]:
                raise ManagementError("Manage delegated fingerprints in Lockly Home")
            if name is None:
                ack = await self.manager.exchange(lock, 0x16, nonce, bytes([1, slot]))
                after = await self.read_fingers(lock, await self.manager.nonce(lock))
                actual = decrypt_reply(ack, str(lock["mc"]), lock_id, 0x16)
                if actual[:2] != b"\x01\x00" or any(e["slot"] == slot for e in after):
                    raise ManagementError("Fingerprint deletion was not confirmed. Refresh before retrying")
                if [e for e in before if e["slot"] != slot] != after:
                    raise ManagementError("Another fingerprint changed. Review access in Lockly Home")
            else:
                cloud = next(
                    (e for e in self.cloud_fingers[lock_id] if e.get("pid") == slot and e.get("dutype") == "F"), None
                )
                if cloud is None:
                    raise ManagementError("This fingerprint has no account record to rename")
                # Names on this firmware are app account metadata. Preserve the
                # existing delegation, OAC permissions and account identifiers.
                request = {
                    k: v
                    for k, v in cloud.items()
                    if k
                    in ("pid", "fpId", "subadm", "oacpriv", "staffNo", "fpCode1", "fpCode2", "uid", "userLoginType")
                }
                request.update(dv=lock_id, fn=name.strip(), isCopy=False)
                await self.cloud("fingerprint/save", request)
                after = await self.read_fingers(lock, await self.manager.nonce(lock))
                current = next((e for e in after if e["slot"] == slot), None)
                if current is None or current["name"] != name.strip():
                    raise ManagementError("The account did not confirm the fingerprint name")
            self.manager.publish(lock)
        return self.manager.public(lock)

    def receive(self, lock: dict, frame: bytes) -> None:
        state = self.enrollment.get(lock["ID"])
        if not state or not state.get("active") or frame[6:8] != b"\x0a\x18":
            return
        # The firmware supplies sensor feedback asynchronously. Do not claim
        # enrollment succeeded until a newly occupied hardware slot is read.
        state["responses"] += 1
        state["message"] = "Sensor feedback received. Follow the lock's prompts, then press Finish."

    async def start_enrollment(self, lock_id: str, name: str) -> dict:
        lock = self.manager.lock(lock_id)
        encode_name(name)
        if self.enrollment.get(lock_id, {}).get("active"):
            raise ManagementError("Fingerprint enrollment is already active")
        async with self.manager.mutex(lock):
            nonce = await self.manager.nonce(lock)
            before = await self.read_fingers(lock, nonce)
            state = {
                "active": True,
                "responses": 0,
                "name": name.strip(),
                "before": [e["slot"] for e in before],
                "expires": time.monotonic() + 60,
                "nonce": nonce,
                "message": "Place and lift your finger as the lock prompts. Press Finish when it completes.",
            }
            self.enrollment[lock_id] = state
            try:
                ack = await self.manager.exchange(lock, 0x14, nonce, b"\x01")
                if decrypt_reply(ack, str(lock["mc"]), lock_id, 0x14)[:2] != b"\x01\x00":
                    raise ManagementError("The lock did not start fingerprint enrollment")
            except BaseException:
                # Starting may have reached the sensor even when its ACK was lost.
                try:
                    await self.manager.exchange(lock, 0x17, nonce, b"\x01")
                except (ManagementError, OSError, TimeoutError, VisionError):
                    pass
                state.update(active=False, message="Enrollment was not confirmed. Refresh before retrying.")
                raise
            self._timers[lock_id] = asyncio.create_task(self._expire(lock_id))
        return self.manager.public(lock)

    async def _expire(self, lock_id: str) -> None:
        try:
            await asyncio.sleep(60)
            await self.finish_enrollment(lock_id, cancel=True)
        except (ManagementError, OSError, TimeoutError, VisionError):
            self.enrollment[lock_id].update(
                active=False, message="Enrollment expired. Refresh fingerprints to check the lock."
            )

    async def finish_enrollment(self, lock_id: str, *, cancel: bool = False) -> dict:
        lock = self.manager.lock(lock_id)
        state = self.enrollment.get(lock_id)
        if not state or not state.get("active"):
            raise ManagementError("There is no active enrollment")
        task = self._timers.pop(lock_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()
        async with self.manager.mutex(lock):
            try:
                # A status query during learning interrupts some sensors. Stop
                # with the nonce that started this enrollment, as the app does.
                ack = await self.manager.exchange(lock, 0x17, state["nonce"], b"\x01")
                if not ack:
                    raise ManagementError(
                        "Enrollment stop was not confirmed. Wait for the sensor to time out, then refresh"
                    )
                state["active"] = False
                after = await self.read_fingers(lock, await self.manager.nonce(lock))
                new = [e for e in after if e["slot"] not in state["before"]]
                if not set(state["before"]).issubset({e["slot"] for e in after}):
                    raise ManagementError("Existing fingerprints changed. Review access in Lockly Home")
                state["message"] = (
                    f"New fingerprint confirmed in slot {new[0]['slot']}."
                    if len(new) == 1
                    else "Enrollment stopped. No new fingerprint was confirmed."
                )
                if len(new) == 1:
                    await self.cloud(
                        "fingerprint/save",
                        {
                            "dv": lock_id,
                            "pid": new[0]["slot"],
                            "fn": state["name"],
                            "subadm": "N",
                            "oacpriv": "N",
                            "staffNo": "",
                            "fpId": "",
                            "fpCode1": "",
                            "fpCode2": "",
                            "isCopy": False,
                        },
                    )
                    named = await self.read_fingers(lock, await self.manager.nonce(lock))
                    if not any(e["slot"] == new[0]["slot"] and e["name"] == state["name"] for e in named):
                        raise ManagementError(
                            "Fingerprint enrolled, but its name was not confirmed. Refresh before renaming"
                        )
                # Never remove a successfully enrolled finger on cancellation.
                if not cancel and len(new) != 1:
                    raise ManagementError(state["message"])
            except (ManagementError, OSError, TimeoutError, VisionError):
                state["message"] = (
                    "Enrollment stop was not confirmed. Refresh after the sensor times out."
                    if state["active"]
                    else "Enrollment stopped. Refresh fingerprints to check the result and name."
                )
                raise
            finally:
                state["active"] = False
                self.manager.publish(lock)
        return self.manager.public(lock)

    async def close(self) -> None:
        for lock_id, state in list(self.enrollment.items()):
            if state.get("active"):
                try:
                    await self.finish_enrollment(lock_id, cancel=True)
                except (ManagementError, OSError, TimeoutError, VisionError):
                    pass
        for task in self._timers.values():
            task.cancel()
