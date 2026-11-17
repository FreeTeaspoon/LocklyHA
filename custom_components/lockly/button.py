"""Explicit status refresh for Vision locks, whose live queries can beep."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LocklyCoordinator
from .const import DOMAIN
from .vision import is_vision_lock


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LocklyRefreshButton(coordinator, lock) for lock in coordinator.locks if is_vision_lock(lock)
    )


class LocklyRefreshButton(CoordinatorEntity, ButtonEntity):
    """Request one current hardware reading without background BLE polling."""

    _attr_has_entity_name = True
    _attr_name = "Refresh status"
    _attr_icon = "mdi:refresh"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        self._lock = lock
        self._attr_unique_id = f"lockly_{lock['ID']}_refresh_status"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, lock["ID"])})

    async def async_press(self) -> None:
        status = await self.coordinator._query_live_status(self._lock)
        if not status:
            raise HomeAssistantError("The Vision hub did not return a current lock status")
        self.coordinator._learn_from_status(self._lock, status)
        self.coordinator._publish_status(self._lock, status)
