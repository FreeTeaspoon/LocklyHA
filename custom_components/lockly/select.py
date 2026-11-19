"""Readback-verified Vision Connect doorbell volume."""
from homeassistant.components.select import SelectEntity
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN
from .vision_features import ManagementError

OPTIONS = ["Mute", "Low", "High"]


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(HubVolumeSelect(coordinator, lock) for lock in coordinator.locks
                       if coordinator._caps_for(lock).lock_type == 97)


class HubVolumeSelect(CoordinatorEntity, SelectEntity):
    _attr_has_entity_name = True
    _attr_name = "Hub doorbell volume"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = OPTIONS

    def __init__(self, coordinator, lock):
        super().__init__(coordinator)
        self._lock_id = lock["ID"]
        self._attr_unique_id = f"lockly_{self._lock_id}_hub_volume"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, self._lock_id)})

    @property
    def available(self):
        return super().available and self.current_option is not None

    @property
    def current_option(self):
        value = self.coordinator.management.hub_volume.get(self._lock_id)
        return OPTIONS[value] if value in (0, 1, 2) else None

    async def async_select_option(self, option):
        try:
            await self.coordinator.management.async_hub_volume(self._lock_id, OPTIONS.index(option))
        except (ManagementError, ValueError) as exc:
            raise HomeAssistantError(str(exc)) from None
