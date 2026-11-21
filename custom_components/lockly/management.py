"""Admin-only WebSocket access; PINs never enter the service/event bus."""
import base64
from pathlib import Path

import aiohttp

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .vision import VisionError
from .vision_features import ManagementError


async def async_setup_management(hass: HomeAssistant) -> None:
    if hass.data.get("lockly_management_registered"):
        return
    websocket_api.async_register_command(hass, websocket_management)
    await hass.http.async_register_static_paths([
        StaticPathConfig("/lockly/management-card.js", str(Path(__file__).parent / "www" / "management-card.js"), False)
    ])
    hass.data["lockly_management_registered"] = True


@websocket_api.websocket_command({
    vol.Required("type"): "lockly/management",
    vol.Optional("lock_id"): str,
    vol.Optional("action", default="get"): vol.In((
        "get", "refresh", "setting", "save_pin", "delete_pin", "history", "hub_volume",
        "fingerprints", "rename_fingerprint", "delete_fingerprint", "enroll_fingerprint", "finish_enrollment",
        "cancel_enrollment", "recordings", "media_start", "media_poll", "media_stop", "media_talk",
        "media_audio", "media_download", "shares", "create_share", "reveal_share", "revoke_share")),
    vol.Optional("value"): vol.All(int, vol.Range(min=0, max=2)),
    vol.Optional("key"): str,
    vol.Optional("enabled"): bool,
    vol.Optional("name"): str,
    vol.Optional("pin", default=""): str,
    vol.Optional("revision"): str,
    vol.Optional("slot"): vol.All(int, vol.Range(min=1, max=255)),
    vol.Optional("schedule"): dict,
    vol.Optional("one_time", default=False): bool,
    vol.Optional("session"): str,
    vol.Optional("clip_id"): str,
    vol.Optional("share_id"): str,
    vol.Optional("export", default=False): bool,
    vol.Optional("audio"): vol.All(str, vol.Length(max=6400)),
})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_management(hass, connection, msg):
    managers = [c.management for c in hass.data.get(DOMAIN, {}).values()]
    try:
        if "lock_id" not in msg:
            if msg["action"] != "get":
                raise ManagementError("Select a lock")
            locks = []
            for manager in managers:
                for lock in manager.coordinator.locks:
                    if manager.coordinator._caps_for(lock).lock_type == 97:
                        locks.append(manager.public(lock))
            connection.send_result(msg["id"], {"locks": locks})
            return
        lock_id = msg["lock_id"]
        manager = next((m for m in managers if any(lock["ID"] == lock_id for lock in m.coordinator.locks)), None)
        if manager is None:
            raise ManagementError("Lock not found")
        lock = manager.lock(lock_id)
        action = msg["action"]
        if action == "refresh":
            result = await manager.async_refresh(lock_id)
        elif action == "hub_volume":
            result = await manager.async_hub_volume(lock_id, msg["value"])
        elif action == "setting":
            result = await manager.async_setting(lock_id, msg["key"], msg["enabled"])
        elif action == "save_pin":
            result = await manager.async_save_pin(
                lock_id, msg["name"], msg["pin"], msg["schedule"], msg.get("slot"), msg.get("revision"),
                one_time=msg["one_time"])
        elif action == "delete_pin":
            await manager.async_delete_pin(lock_id, msg["slot"], msg.get("revision"))
            result = manager.public(lock)
        elif action == "history":
            # Use the same path as read_access_log to update HA's Last Access sensor.
            records = await manager.async_history(lock_id)
            await manager.coordinator._poll_lock_log(lock, records_override=records)
            result = manager.public(lock)
        elif action == "fingerprints":
            result = await manager.access.refresh_fingers(lock_id)
        elif action in ("rename_fingerprint", "delete_fingerprint"):
            result = await manager.access.change_finger(lock_id, msg["slot"], msg["revision"],
                                                        msg["name"] if action == "rename_fingerprint" else None)
        elif action == "enroll_fingerprint":
            result = await manager.access.start_enrollment(lock_id, msg["name"])
        elif action in ("finish_enrollment", "cancel_enrollment"):
            result = await manager.access.finish_enrollment(lock_id, cancel=action == "cancel_enrollment")
        elif action == "recordings":
            result = await manager.media.list_recordings(lock_id)
        elif action == "media_start":
            result = await manager.media.start(lock_id, connection.user.id, msg.get("clip_id"), msg["export"])
        elif action.startswith("media_"):
            session = manager.media.get(msg["session"], connection.user.id, lock_id)
            result = {}
            if action == "media_poll":
                result = session.poll()
            elif action == "media_stop":
                await session.close()
                manager.media.sessions.pop(msg["session"], None)
            elif action == "media_talk":
                await session.talk(msg["enabled"])
            elif action == "media_audio":
                session.send(msg["audio"])
            elif action == "media_download":
                if not session.ended or not session.file:
                    raise ManagementError("Wait for the recording export to finish")
                result = {"file": base64.b64encode(session.file).decode(), "name": "lockly-recording.mp4"}
        elif action == "shares":
            result = await manager.access.refresh_shares(lock_id)
        elif action == "create_share":
            result = await manager.access.create_share(lock_id, msg["slot"], msg["revision"])
        elif action == "reveal_share":
            result = await manager.access.reveal_share(lock_id, msg["share_id"], msg["revision"])
        elif action == "revoke_share":
            result = await manager.access.revoke_share(lock_id, msg["share_id"], msg["revision"])
        else:
            result = manager.public(lock)
        connection.send_result(msg["id"], result)
    except ManagementError as exc:
        connection.send_error(msg["id"], "management_failed", str(exc))
    except KeyError:
        connection.send_error(msg["id"], "invalid_request", "The operation is missing a required field")
    except (OSError, TimeoutError, aiohttp.ClientError, VisionError):
        connection.send_error(msg["id"], "connection_failed", "The connection failed. Refresh before retrying")
