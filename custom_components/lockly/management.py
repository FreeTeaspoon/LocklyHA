"""Admin-only WebSocket access; PINs never enter the service/event bus."""
from pathlib import Path

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN
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
        "get", "refresh", "setting", "save_pin", "delete_pin", "history", "hub_volume")),
    vol.Optional("value"): vol.All(int, vol.Range(min=0, max=2)),
    vol.Optional("key"): str,
    vol.Optional("enabled"): bool,
    vol.Optional("name"): str,
    vol.Optional("pin", default=""): str,
    vol.Optional("revision"): str,
    vol.Optional("slot"): vol.All(int, vol.Range(min=1, max=255)),
    vol.Optional("schedule"): dict,
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
                lock_id, msg["name"], msg["pin"], msg["schedule"], msg.get("slot"), msg.get("revision"))
        elif action == "delete_pin":
            await manager.async_delete_pin(lock_id, msg["slot"], msg.get("revision"))
            result = manager.public(lock)
        elif action == "history":
            # Use the same path as read_access_log to update HA's Last Access sensor.
            records = await manager.async_history(lock_id)
            await manager.coordinator._poll_lock_log(lock, records_override=records)
            result = manager.public(lock)
        else:
            result = manager.public(lock)
        connection.send_result(msg["id"], result)
    except ManagementError as exc:
        connection.send_error(msg["id"], "management_failed", str(exc))
    except KeyError:
        connection.send_error(msg["id"], "invalid_request", "The operation is missing a required field")
