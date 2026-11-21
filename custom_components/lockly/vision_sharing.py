"""Lockly's legacy family eKeys, with explicit credential selection and readback."""

from __future__ import annotations

import hashlib
import hmac
import json

from .api import derive_aes_key, des3_encrypt, des3_decrypt, encrypt_master_code, sha256_hex
from .vision_features import ManagementError, PIN_SLOTS

# Vendor transport key from libkey.so, not an account or device credential.
_EKEY_KEY = bytes.fromhex("62d5fae436346ac7e2aa951a73b154283a43d515b0de90b7")


def wrap_ekey(value: dict) -> str:
    return des3_encrypt(_EKEY_KEY, json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def build_ekey(lock: dict, credential) -> tuple[str, str]:
    """FamilyUserBean / KeyFactory.d, restricted to an ordinary always PIN."""
    if credential.slot not in PIN_SLOTS or not credential.public()["editable"]:
        raise ManagementError("Select an ordinary guest PIN to share")
    if credential.public()["schedule"]["type"] != "always":
        raise ManagementError("Family eKeys require an always-access PIN")
    reversed_mc = str(lock["mc"])[::-1]
    base = {
        "aesKey": derive_aes_key(reversed_mc, lock["ID"]).hex().upper(),
        "key": encrypt_master_code(reversed_mc, lock["ID"]),
        "id": lock["ID"],
        "pwd": credential.pin,
        "pwdid": str(credential.slot),
        "na": lock.get("blename", ""),
        "sna": lock.get("na", "Lockly"),
        "un": credential.name,
        "lockType": 97,
        "version": lock.get("fwv", ""),
        "v": "104",
        "tz": str(lock.get("tz", "8")),
        "bt": 0,
        "et": 0,
        "cyc": 0,
        "isLongTerm": "0",
        "byLongTerm": "0",
        "oacPermission": "0",
        "notBackupName": False,
        "appKey": False,
        "ad": "",
        "ap": "",
        "re": "",
    }
    base["enc"] = hashlib.md5(
        "".join(("1" if v else "0") if isinstance(v, bool) else str(v) for _, v in sorted(base.items())).encode()
    ).hexdigest()
    # Local door access only. Never grant camera, remote hub or settings access
    # by copying the owner's P2P/IoT identity into a newly created guest key.
    extension = {
        "ad": "",
        "ap": "",
        "camModel": "",
        "clientId": "",
        "gwModel": "",
        "gwVersion": "",
        "hlp": "0",
        "hsp": "0",
        "hubid": "",
        "hubver": "",
        "iotdm": "",
        "iothost": "",
        "iotprodkey": "",
        "iotsecret": "",
        "permission": 0,
        "rflist": [],
        "role": "",
        "sfwv": "",
        "hubPriviledge": "N",
        "dnt": lock.get("na", "Lockly"),
    }
    return wrap_ekey(base), wrap_ekey(extension)


class SharingMixin:
    async def read_shares(self, lock: dict) -> list[dict]:
        response = await self.cloud("getEkeyList", {"dv": lock["ID"], "ekeyType": ""})
        entries = response.get("tp")
        if not isinstance(entries, list) or any(not isinstance(e, dict) or not e.get("token") for e in entries):
            raise ManagementError("Lockly returned an unsupported eKey list")
        self.raw_shares[lock["ID"]] = entries
        public = []
        for entry in entries:
            # Use an opaque reference, never a token, as the public identifier.
            ident = hmac.new(self.manager._revision_key, str(entry["token"]).encode(), hashlib.sha256).hexdigest()
            slot = entry.get("pwdId")
            try:
                decoded = json.loads(des3_decrypt(_EKEY_KEY, entry.get("tempPwd", "")))
                slot = int(decoded["pwdid"])
            except (ValueError, KeyError, TypeError, IndexError):
                if not str(slot).isascii() or not str(slot).isdigit() or len(str(slot)) > 3:
                    slot = None
            public.append(
                {
                    "id": ident,
                    "name": entry.get("newName")
                    or " ".join(str(entry.get(k) or "") for k in ("firstName", "lastName")).strip()
                    or "Shared eKey",
                    "type": entry.get("ekeyType"),
                    "slot": slot,
                    "status": entry.get("status"),
                    "revision": self.revision(entry),
                }
            )
        self.shares[lock["ID"]] = public
        return public

    async def refresh_shares(self, lock_id: str) -> dict:
        lock = self.manager.lock(lock_id)
        async with self.manager.mutex(lock):
            await self.read_shares(lock)
        return self.manager.public(lock)

    async def selected_share(self, lock: dict, ident: str, revision: str) -> dict:
        entries = await self.read_shares(lock)
        index = next((i for i, e in enumerate(entries) if e["id"] == ident), None)
        if index is None or not revision or not hmac.compare_digest(entries[index]["revision"], revision):
            raise ManagementError("This eKey changed. Refresh before continuing")
        return self.raw_shares[lock["ID"]][index]

    async def reveal_share(self, lock_id: str, ident: str, revision: str) -> dict:
        lock = self.manager.lock(lock_id)
        async with self.manager.mutex(lock):
            entry = await self.selected_share(lock, ident, revision)
            return {"token": entry["token"]}

    async def revoke_share(self, lock_id: str, ident: str, revision: str) -> dict:
        lock = self.manager.lock(lock_id)
        async with self.manager.mutex(lock):
            entry = await self.selected_share(lock, ident, revision)
            others = {self.revision(e) for e in self.raw_shares[lock_id] if e is not entry}
            c = self.manager.coordinator
            await self.cloud(
                "rmtoken", {"acct": c.email, "dv": lock_id, "pw": sha256_hex(c.password), "tp": entry["token"]}
            )
            await self.read_shares(lock)
            after = self.raw_shares[lock_id]
            if any(e["token"] == entry["token"] for e in after) or others != {self.revision(e) for e in after}:
                raise ManagementError("eKey revocation was not confirmed. Refresh before retrying")
        return self.manager.public(lock)

    async def create_share(self, lock_id: str, slot: int, revision: str) -> dict:
        lock = self.manager.lock(lock_id)
        async with self.manager.mutex(lock):
            credentials = await self.manager.read_credentials(lock, await self.manager.nonce(lock))
            credential = next((e for e in credentials if e.slot == slot), None)
            if credential is None:
                raise ManagementError("That PIN no longer exists")
            self.manager.verify_revision(credential, revision)
            tp, tp2 = build_ekey(lock, credential)
            directory = await self.read_directory(lock)
            matching = [e for e in directory if e.get("dutype") == "P" and str(e.get("pid")) == str(slot)]
            if len(matching) > 1:
                raise ManagementError("This PIN has ambiguous account records. Manage it in Lockly Home")
            row = dict(matching[0]) if matching else {"pid": slot, "dutype": "P", "fn": credential.name, "ln": ""}
            if any(str(row.get(k) or "N").upper() not in ("N", "0") for k in ("subadm", "oacpriv", "dpriv")):
                raise ManagementError("Manage delegated account permissions in Lockly Home")
            before = await self.read_shares(lock)
            if any(str(e.get("slot")) == str(slot) for e in before):
                raise ManagementError("This PIN already has an eKey. Reveal the existing key")
            c = self.manager.coordinator
            others = {self.revision(e) for e in self.raw_shares[lock_id]}
            response = await self.cloud(
                "gentptoken",
                {
                    "acct": c.email,
                    "dv": lock_id,
                    "tp": tp,
                    "tp2": tp2,
                    "extendtp": "",
                    "tpt": "M",
                    "oldtk": "",
                    "stdate": 0,
                    "endate": 0,
                    "isAddType": "Y",
                },
            )
            try:
                token = des3_decrypt(c.des3_key, response["token"]).decode("utf-8")
            except (KeyError, ValueError, TypeError, UnicodeError):
                raise ManagementError("The eKey may have been created. Refresh before retrying") from None
            if not token:
                raise ManagementError("Lockly returned an empty eKey. Refresh before retrying")
            # gentptoken generates the key. Lockly Home then saves its selected
            # directory entry and password profile using a single-row delta.
            row.update(token=token, uuid=lock_id)
            for field in ("subadm", "oacpriv", "dpriv"):
                row.setdefault(field, "N")
            try:
                await self.cloud(
                    "du/save",
                    {
                        "acct": c.email,
                        "dv": lock_id,
                        "pid": 0,
                        "usrarr": [row],
                        "pwData": {
                            "dv": lock_id,
                            "stdate": 0,
                            "endate": 0,
                            "na": row.get("fn", credential.name),
                            "lastName": row.get("ln", ""),
                            "pw": credential.pin,
                            "pid": str(slot),
                            "oacType": "ekey",
                            "pwType": "FAMILY",
                            "token": token,
                        },
                    },
                )
            except ManagementError:
                # Never repeat the uncertain profile write. Revoke only this
                # newly generated token, then verify the original keys remain.
                try:
                    await self.cloud(
                        "rmtoken", {"acct": c.email, "dv": lock_id, "pw": sha256_hex(c.password), "tp": token}
                    )
                    await self.read_shares(lock)
                    if {self.revision(e) for e in self.raw_shares[lock_id]} != others:
                        raise ManagementError("Unconfirmed eKey cleanup")
                except ManagementError:
                    raise ManagementError(
                        "The profile save and eKey cleanup were not confirmed. Refresh eKeys in Lockly Home"
                    ) from None
                raise ManagementError(
                    "The profile save failed. Its new eKey was revoked; refresh before trying again"
                ) from None
            await self.read_shares(lock)
            after = self.raw_shares[lock_id]
            if (
                not any(e["token"] == token for e in after)
                or {self.revision(e) for e in after if e["token"] != token} != others
            ):
                raise ManagementError("The eKey was not confirmed. Refresh before retrying")
        return self.manager.public(lock)
