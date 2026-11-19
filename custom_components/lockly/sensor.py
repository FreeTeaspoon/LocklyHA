"""Lockly sensor entities."""
from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.helpers.entity import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LocklyCoordinator
from .api import describe_open_type
from .const import BATTERY_MAX_V, BATTERY_MIN_V, DOMAIN
from .vision_features import s8_battery_percent

_LOGGER = logging.getLogger(__name__)

def _voltage_to_pct(raw: int) -> int:
    """Convert raw wakeup_voltage (10 mV units) to a clamped battery percentage.

    Voltage range for 4×AA: BATTERY_MIN_V (empty) to BATTERY_MAX_V (full).
    raw * 0.01 = volts  (raw is in units of 10 mV = 0.01 V)
    """
    volts = raw * 0.01
    pct = (volts - BATTERY_MIN_V) / (BATTERY_MAX_V - BATTERY_MIN_V) * 100
    return max(0, min(100, round(pct)))


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: LocklyCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for lock in coordinator.locks:
        entities.append(LocklyBatterySensor(coordinator, lock))
        entities.append(LocklyLastAccessSensor(coordinator, lock))
        entities.append(LocklyVoltageSensor(coordinator, lock))
        entities.append(LocklySignalSensor(coordinator, lock, "ble_rssi", "Hub link signal"))
        entities.append(LocklySignalSensor(coordinator, lock, "hub_wifi_rssi", "Hub WiFi signal"))
    async_add_entities(entities)


def _lock_display_name(lock_data: dict, lock_id: str) -> str:
    return lock_data.get("na") or lock_data.get("blename") or lock_id


class LocklyBatterySensor(CoordinatorEntity, SensorEntity):
    """Battery level for a Lockly lock.

    Reported percentages take precedence. PGD898S voltage estimates use the
    app's model-specific curve. Binary warnings remain attributes, never a
    fabricated 10% or 90% reading.
    """

    _attr_has_entity_name = True
    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._attr_unique_id = f"lockly_{lock_id}_battery"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock, lock_id),
            manufacturer="Lockly",
            model=lock.get("mod") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def available(self) -> bool:
        return super().available and self._lock_data.get("vision_connected", True)

    @property
    def native_value(self) -> int | None:
        d = self._lock_data

        # The lock's own number, pushed on the MQTT channel. It outranks the
        # voltage curve below because it is the figure the lock and the Lockly
        # app agree on rather than an inference from a wakeup reading.
        pct = d.get("battery_percent")
        if pct is not None:
            return pct

        # Real voltage — present after a live BLE query (startup or post-command).
        raw_v = d.get("wakeup_voltage")
        if raw_v is not None and not d.get("battery_invalid"):
            if self.coordinator._caps_for(d).lock_type == 97:
                return s8_battery_percent(raw_v)
            return _voltage_to_pct(raw_v)

        # Binary flag — from cloud cache (cachedstatus) or invalid voltage.
        low = d.get("low_battery")
        if low is None:
            return None  # no data yet → unavailable
        return None  # A binary warning is not a percentage.

    @property
    def extra_state_attributes(self) -> dict:
        d = self._lock_data
        attrs: dict = {}
        # Which source produced the reading. 90 % from a sentinel and 90 %
        # measured mean very different things to someone setting a low-battery
        # alert, and nothing else on the entity distinguishes them.
        if d.get("battery_percent") is not None:
            attrs["source"] = "reported"
        elif d.get("wakeup_voltage") is not None and not d.get("battery_invalid"):
            attrs["source"] = ("Lockly Home S8 voltage thresholds"
                               if self.coordinator._caps_for(d).lock_type == 97 else "voltage")
            attrs["estimated"] = True
        elif d.get("low_battery") is not None:
            attrs["source"] = "low battery flag"
        raw_v = d.get("wakeup_voltage")
        if raw_v is not None:
            attrs["voltage"] = round(raw_v * 0.01, 2)
        low = d.get("low_battery")
        if low is not None:
            attrs["low_battery"] = low
        if d.get("battery_invalid"):
            attrs["battery_invalid"] = True
        return attrs


class LocklyLastAccessSensor(CoordinatorEntity, SensorEntity):
    """Shows who most recently accessed the lock and when."""

    _attr_has_entity_name = True
    _attr_name = "Last Access"
    _attr_icon = "mdi:account-clock"

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._attr_unique_id = f"lockly_{lock_id}_last_access"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock, lock_id),
            manufacturer="Lockly",
            model=lock.get("mod") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def native_value(self) -> str | None:
        """Who last opened the lock.

        The coordinator resolves the credential slot to a name where it can.
        When it cannot, report the slot rather than "Unknown" — a slot number is
        at least actionable, and the old behaviour reported every keypad and
        fingerprint entry as Unknown because those carry no name in the event.
        """
        event = self._lock_data.get("last_access_event")
        if not event:
            return None
        operator = event.get("operator")
        if operator:
            return operator
        pid = event.get("pid")
        if pid is None:
            # No credential attached — an auto-lock or door event rather than
            # somebody unlocking.  Saying "Unknown person" would be wrong; there
            # was no person.
            return "No credential"
        if event.get("operator_candidates"):
            return f"Slot {pid} (ambiguous)"
        return f"Slot {pid}"

    @property
    def extra_state_attributes(self) -> dict:
        event = self._lock_data.get("last_access_event")
        if not event:
            return {}
        attrs: dict = {
            # Raw numeric code, plus a readable name where the code is known.
            "event_code": event.get("co"),
            "event_type": describe_open_type(event.get("co")),
            "credential_slot": event.get("pid"),
            "timestamp": event.get("tm"),
            "event_id": event.get("id"),
        }
        candidates = event.get("operator_candidates")
        if candidates:
            # Slot numbers are namespaced per credential type, so a slot can map
            # to more than one user and the event does not say which type it was.
            attrs["operator_candidates"] = candidates
        return attrs


class LocklySignalSensor(CoordinatorEntity, SensorEntity):
    """Radio signal strength, populated on demand by `lockly.read_signal`.

    Diagnostic and disabled by default. The value is a snapshot rather than a
    live measurement: it comes from a broker round trip that only happens when
    the service is called, because the reading is only meaningful next to a
    physical change such as moving the hub. Polling it would add traffic for a
    number that does not move on its own.

    `unknown` until the service has been called, and on hubs that are not on the
    MQTT channel it stays that way — those answer `3005 device is offline`.
    """

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = "dBm"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(
        self, coordinator: LocklyCoordinator, lock: dict, key: str, label: str
    ) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._key = key
        self._attr_name = label
        self._attr_unique_id = f"lockly_{lock_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock, lock_id),
            manufacturer="Lockly",
            model=lock.get("mod") or "Smart Lock",
        )

    @property
    def native_value(self) -> int | None:
        return (self.coordinator.data.get(self._lock_id) or {}).get(self._key)

    @property
    def extra_state_attributes(self) -> dict:
        d = self.coordinator.data.get(self._lock_id) or {}
        attrs: dict = {}
        if self._key == "ble_rssi":
            # Lockly's own thresholds: -70 or better is strong, -80 or worse is
            # weak. Staleness matters because the app discards a reading more
            # than 15 seconds behind the hub's clock.
            attrs["age_seconds"] = d.get("ble_rssi_age_s")
            attrs["stale"] = d.get("ble_rssi_stale")
        else:
            attrs["ssid"] = d.get("hub_wifi_ssid")
            attrs["hub_firmware"] = d.get("hub_firmware")
        return {k: v for k, v in attrs.items() if v is not None}


class LocklyVoltageSensor(LocklyBatterySensor):
    """Raw battery voltage, independent of percentage estimates."""

    _attr_name = "Battery voltage"
    _attr_device_class = SensorDeviceClass.VOLTAGE
    _attr_native_unit_of_measurement = "V"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, lock):
        super().__init__(coordinator, lock)
        self._attr_unique_id = f"lockly_{lock['ID']}_battery_voltage"

    @property
    def native_value(self) -> float | None:
        d = self._lock_data
        raw = d.get("wakeup_voltage")
        return round(raw * .01, 2) if raw is not None and not d.get("battery_invalid") else None

    @property
    def extra_state_attributes(self) -> dict:
        return {}
