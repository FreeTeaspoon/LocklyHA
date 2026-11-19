"""Physical PGD898S settings, changed with readback and preserved unrelated bits."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN
from .vision_features import ManagementError, SETTINGS

LABELS = {"pin_genie": "PIN Genie", "keypad_sound": "Keypad sound",
          "auto_lock_enabled": "Auto-lock", "bluetooth_sound": "Bluetooth sound",
          "fingerprint_sound": "Fingerprint enrollment sound"}


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(SettingSwitch(coordinator, lock, key)
                       for lock in coordinator.locks if coordinator._caps_for(lock).lock_type == 97
                       for key in SETTINGS)


class SettingSwitch(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, lock, key):
        super().__init__(coordinator)
        self._lock_id, self._key = lock["ID"], key
        self._attr_unique_id = f"lockly_{self._lock_id}_{key}"
        self._attr_name = LABELS[key]
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, self._lock_id)})

    @property
    def available(self):
        group, _ = SETTINGS[self._key]
        return super().available and group in self.coordinator.management.settings.get(self._lock_id, {})

    @property
    def is_on(self):
        group, mask = SETTINGS[self._key]
        value = self.coordinator.management.settings.get(self._lock_id, {}).get(group)
        return None if value is None else bool(value & mask)

    async def _set(self, enabled):
        try:
            await self.coordinator.management.async_setting(self._lock_id, self._key, enabled)
        except ManagementError as exc:
            raise HomeAssistantError(str(exc)) from None

    async def async_turn_on(self, **kwargs):
        await self._set(True)

    async def async_turn_off(self, **kwargs):
        await self._set(False)
