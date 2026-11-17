"""On-demand Vision live camera, decoded locally without a phone bridge."""
from __future__ import annotations

import asyncio
import logging
import time
from fractions import Fraction

import av
from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .vision import VisionClient, VisionError, is_vision_lock

_LOGGER = logging.getLogger(__name__)


def decode_jpeg(decoder, encoder, packet: bytes) -> bytes | None:
    """Decode one vendor frame and encode a browser-compatible still."""
    result = None
    for frame in decoder.decode(av.Packet(packet)):
        frame = frame.reformat(width=960, height=540, format="yuvj420p")
        frame.pts = None
        output = b"".join(bytes(p) for p in encoder.encode(frame))
        if output:
            result = output
    return result


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(VisionCamera(lock) for lock in coordinator.locks if is_vision_lock(lock))


class VisionCamera(Camera):
    """Live view starts on demand and stops after viewers stop requesting frames."""

    _attr_has_entity_name = True
    _attr_name = "Camera"
    _attr_is_streaming = False
    _attr_frame_interval = 0.5

    def __init__(self, lock: dict) -> None:
        super().__init__()
        self._attr_unique_id = f"lockly_{lock['ID']}_camera"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, lock["ID"])})
        self._client = VisionClient(str(lock["p2pdid"]), str(lock["p2ppw"]), on_video=self._receive)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=8)
        self._worker: asyncio.Task | None = None
        self._ready = asyncio.Event()
        self._jpeg: bytes | None = None
        self._jpeg_at = 0.0
        self._requested_at = 0.0
        self._start_lock = asyncio.Lock()
        self._need_keyframe = True

    def _receive(self, frame: bytes, codec: int, keyframe: bool) -> None:
        if self._queue.full():
            while not self._queue.empty():
                self._queue.get_nowait()
            self._need_keyframe = True
        if self._need_keyframe:
            if not keyframe:
                return
            self._need_keyframe = False
        self._queue.put_nowait((frame, codec))

    async def _run(self) -> None:
        decoder = encoder = None
        codec = None
        try:
            await self._client.async_start_video()
            while time.monotonic() - self._requested_at < 10:
                try:
                    frame, next_codec = await asyncio.wait_for(self._queue.get(), 2)
                except TimeoutError:
                    continue
                if codec != next_codec:
                    codec = next_codec
                    decoder = await self.hass.async_add_executor_job(
                        av.CodecContext.create, "hevc" if codec == 5 else "h264", "r"
                    )
                    decoder.thread_count = 1
                    encoder = await self.hass.async_add_executor_job(av.CodecContext.create, "mjpeg", "w")
                    encoder.width, encoder.height, encoder.pix_fmt = 960, 540, "yuvj420p"
                    encoder.time_base = Fraction(1, 20)
                    encoder.thread_count = 1
                jpeg = await self.hass.async_add_executor_job(decode_jpeg, decoder, encoder, frame)
                if jpeg:
                    self._jpeg, self._jpeg_at = jpeg, time.monotonic()
                    self._ready.set()
        except (VisionError, OSError, av.FFmpegError) as exc:
            self._jpeg = None
            _LOGGER.warning("Lockly Vision camera: %s", exc)
        finally:
            try:
                await asyncio.wait_for(self._client.async_stop_video(), 2)
            except (VisionError, OSError, TimeoutError):
                pass
            await self._client._disconnect()
            self._ready.set()

    async def async_camera_image(self, width: int | None = None, height: int | None = None) -> bytes | None:
        self._requested_at = time.monotonic()
        async with self._start_lock:
            if self._worker is None or self._worker.done():
                self._ready.clear()
                self._need_keyframe = True
                while not self._queue.empty():
                    self._queue.get_nowait()
                self._worker = self.hass.async_create_background_task(self._run(), "Lockly Vision camera")
        if self._jpeg and time.monotonic() - self._jpeg_at < 2:
            return self._jpeg
        self._ready.clear()
        try:
            await asyncio.wait_for(self._ready.wait(), 15)
        except TimeoutError:
            return None
        return self._jpeg if time.monotonic() - self._jpeg_at < 3 else None

    async def async_will_remove_from_hass(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
        await self._client.async_close()
        await super().async_will_remove_from_hass()
