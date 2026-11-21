"""Bounded, administrator-owned live audio and recording playback sessions."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta
from fractions import Fraction
import io
import secrets
import struct
import time
from zoneinfo import ZoneInfo

import av

from .vision import VisionClient, VisionError
from .vision_audio import ADPCMDecoder
from .vision_features import ManagementError


def camera_time(value: datetime) -> bytes:
    return struct.pack(
        "<H6B", value.year, value.month, value.day, (value.weekday() + 1) % 7, value.hour, value.minute, value.second
    )


def parse_recordings(data: bytes, timezone: str) -> tuple[list[dict], bool]:
    if len(data) < 16:
        raise ManagementError("The hub returned an incomplete recording list")
    _channel, total, count = struct.unpack_from("<3I", data)
    if count > 1000 or len(data) != 16 + count * 20 or data[13] not in (0, 1):
        raise ManagementError("The hub returned an invalid recording list")
    events = []
    for index in range(count):
        raw = data[16 + index * 20 : 36 + index * 20]
        year, month, day, _week, hour, minute, second = struct.unpack_from("<H6B", raw)
        try:
            date = datetime(year, month, day, hour, minute, second, tzinfo=ZoneInfo(timezone))
        except ValueError:
            raise ManagementError("The hub returned an invalid recording date") from None
        events.append(
            {
                "id": raw.hex(),
                "time": date.isoformat(),
                "event": raw[8],
                "duration": struct.unpack_from("<I", raw, 12)[0],
            }
        )
    return events, bool(data[13])


class MediaDecoder:
    """Codec work runs serially in an executor; decoded media never enters logs."""

    def __init__(self, export: bool = False) -> None:
        self.video = self.jpeg = self.audio = self.resampler = None
        self.codec = self.audio_codec = None
        self.file = io.BytesIO() if export else None
        self.output = self.video_out = self.audio_out = None
        self.video_pts = self.audio_pts = 0
        self.origin = None

    def open_export(self) -> None:
        if self.file is None or self.output is not None:
            return
        self.output = av.open(self.file, "w", format="mp4")
        self.video_out = self.output.add_stream("libx264", rate=20)
        self.video_out.width, self.video_out.height = 960, 540
        self.video_out.pix_fmt = "yuv420p"
        self.video_out.time_base = Fraction(1, 1000)
        self.video_out.codec_context.time_base = Fraction(1, 1000)
        self.video_out.codec_context.thread_count = 1
        self.video_out.options = {"preset": "ultrafast", "crf": "26", "bf": "0"}
        self.audio_out = self.output.add_stream("aac", rate=48000)
        self.audio_out.layout = "mono"
        self.export_resampler = av.AudioResampler(format="fltp", layout="mono", rate=48000)

    def mux(self, stream, frame) -> None:
        for packet in stream.encode(frame):
            self.output.mux(packet)
        if self.file.tell() > 20 * 1024 * 1024:
            raise ManagementError("The clip exceeds the 20 MB export limit")

    def decode(self, data: bytes, codec: int, audio: bool, pts: int | None = None) -> bytes | None:
        if self.file is not None:
            self.open_export()
            if pts is None:
                raise ManagementError("The recording has no playback timestamps")
            if self.origin is None:
                self.origin = pts
            # The SDK's playback clock is an unsigned millisecond counter.
            relative = (pts - self.origin) & 0xFFFFFFFF
            if relative > 120000:
                raise ManagementError("The recording timestamp exceeds the session limit")
        else:
            relative = 0
        if audio:
            if codec not in (1, 80, 81, 82, 83, 84):
                raise ManagementError("This camera audio codec is not supported")
            if self.audio_codec != codec:
                self.audio_codec = codec
                if codec == 83:
                    self.adpcm = ADPCMDecoder()
                else:
                    names = {80: "aac", 81: "pcm_mulaw", 84: "pcm_s16le"}
                    self.audio = av.CodecContext.create(names.get(codec, "pcm_alaw"), "r")
                    self.audio.sample_rate = 8000
                    self.audio.layout = "mono"
                self.resampler = av.AudioResampler(format="s16", layout="mono", rate=8000)
            result = bytearray()
            if codec == 83:
                raw = self.adpcm.decode(data)
                frame = av.AudioFrame(format="s16", layout="mono", samples=len(raw) // 2)
                frame.planes[0].update(raw)
                frame.sample_rate = 8000
                frames = [frame]
            else:
                frames = self.audio.decode(av.Packet(data))
            for frame in frames:
                for pcm in self.resampler.resample(frame):
                    result.extend(bytes(pcm.planes[0])[: pcm.samples * 2])
                    if self.file is not None:
                        pcm.pts = max(self.audio_pts, relative * 8)
                        pcm.time_base = Fraction(1, 8000)
                        self.audio_pts = pcm.pts + pcm.samples
                        for converted in self.export_resampler.resample(pcm):
                            self.mux(self.audio_out, converted)
            return bytes(result)
        if self.codec != codec:
            self.codec = codec
            self.video = av.CodecContext.create("hevc" if codec == 5 else "h264", "r")
            self.video.thread_count = 1
            self.jpeg = av.CodecContext.create("mjpeg", "w")
            self.jpeg.width, self.jpeg.height, self.jpeg.pix_fmt = 960, 540, "yuvj420p"
            self.jpeg.time_base = Fraction(1, 20)
            self.jpeg.thread_count = 1
        image = None
        packet = av.Packet(data)
        if pts is not None:
            packet.pts = relative
            packet.time_base = Fraction(1, 1000)
        for frame in self.video.decode(packet):
            if self.file is not None:
                out = frame.reformat(width=960, height=540, format="yuv420p")
                out.pts = max(self.video_pts, frame.pts if frame.pts is not None else relative)
                out.time_base = Fraction(1, 1000)
                self.video_pts = out.pts + 1
                self.mux(self.video_out, out)
            frame = frame.reformat(width=960, height=540, format="yuvj420p")
            frame.pts = None
            frame.time_base = Fraction(1, 20)
            encoded = b"".join(bytes(p) for p in self.jpeg.encode(frame))
            if encoded:
                image = encoded
        return image

    def finish(self) -> bytes | None:
        if self.output:
            try:
                for frame in self.export_resampler.resample(None):
                    self.mux(self.audio_out, frame)
                self.mux(self.audio_out, None)
                self.mux(self.video_out, None)
            finally:
                self.output.close()
            if self.file.tell() > 20 * 1024 * 1024:
                raise ManagementError("The clip exceeds the 20 MB export limit")
        return self.file.getvalue() if self.file and self.video_pts else None


class MediaSession:
    def __init__(self, lock: dict, owner: str, record: bytes | None = None, export: bool = False) -> None:
        self.owner, self.token = owner, secrets.token_urlsafe(24)
        self.client = VisionClient(
            str(lock["p2pdid"]), str(lock["p2ppw"]), on_video=self.video, on_audio=self.audio, on_playback=self.playback
        )
        self.record = record
        self.decoder = MediaDecoder(export)
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=24)
        self.jpeg: bytes | None = None
        self.pcm = bytearray()
        self.last_poll = self.started = time.monotonic()
        self.error: str | None = None
        self.ended = self.talking = False
        self._input_ended = False
        self.file: bytes | None = None
        self.worker: asyncio.Task | None = None
        self.need_keyframe = True
        self._audio_sent = 0
        self._audio_start = 0.0
        self._closing = False
        self.export = export
        self.lock_id = lock["ID"]

    def video(self, data: bytes, codec: int, key: bool) -> None:
        if self.need_keyframe and not key:
            return
        self.need_keyframe = False
        self.feed(data, codec, False)

    def audio(self, data: bytes, codec: int) -> None:
        self.feed(data, codec, True)

    def playback(self, data: bytes, flag: int, kind: int, pts: int) -> None:
        if flag == 553649432:
            self._input_ended = True
        elif flag == 428216306:
            self.feed(data, kind, True, pts)
        elif flag in (428213528, 428216305):
            if self.need_keyframe and kind not in (1, 17):
                return
            self.need_keyframe = False
            self.feed(data, 5 if kind in (17, 18) else 4, False, pts)

    def feed(self, data: bytes, codec: int, audio: bool, pts: int | None = None) -> None:
        if self.ended or self._input_ended:
            return
        if self.queue.full():
            # ADPCM keeps state across packets. A dropped packet corrupts later
            # audio, and dropped video invalidates an export. Close explicitly.
            self.error = "Camera media exceeded the decode buffer. Close and reopen the camera"
            self.ended = True
            return
        self.queue.put_nowait((data, codec, audio, pts))

    async def start(self) -> None:
        try:
            if self.record is None:
                await self.client.async_start_video()
                await self.client.async_audio(True)
            else:
                await self.client._connect()
                payload = struct.pack("<3I", 0, 16, 0) + self.record[:8] + self.record[16:20] + self.client._token
                response = await self.client.async_hub_request(794, payload, {795})
                if len(response) < 8 or struct.unpack_from("<I", response)[0] != 16:
                    raise ManagementError("The hub did not start recording playback")
            self.worker = asyncio.create_task(self.run())
        except BaseException:
            await self.client.async_close()
            raise

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while time.monotonic() - self.last_poll < 10 and time.monotonic() - self.started < 120:
                if self.error or self._input_ended and self.queue.empty():
                    break
                try:
                    data, codec, audio, pts = await asyncio.wait_for(self.queue.get(), 1)
                except TimeoutError:
                    continue
                work = loop.run_in_executor(None, self.decoder.decode, data, codec, audio, pts)
                try:
                    decoded = await asyncio.shield(work)
                except asyncio.CancelledError:
                    # Codec contexts must finish their current call before flush.
                    await work
                    raise
                if decoded:
                    if audio:
                        self.pcm.extend(decoded)
                        if len(self.pcm) > 32000:
                            del self.pcm[:-32000]
                    else:
                        self.jpeg = decoded
        except (VisionError, ManagementError, OSError, av.FFmpegError) as exc:
            self.error = (
                str(exc) if isinstance(exc, (VisionError, ManagementError)) else "Could not decode camera media"
            )
        finally:
            try:
                self.file = await loop.run_in_executor(None, self.decoder.finish)
                if self.error or (self.export and not self._input_ended):
                    self.file = None
                    self.error = self.error or "Playback exceeded the session limit. No complete file was saved"
            except (OSError, av.FFmpegError, ManagementError):
                self.error = "Could not finish the recording export"
            await self.stop_transport()
            self.ended = True

    async def stop_transport(self) -> None:
        if self._closing:
            return
        self._closing = True
        try:
            if self.client.connected:
                if self.talking:
                    await asyncio.wait_for(self.client.async_talk(False), 2)
                if self.record is None:
                    await asyncio.wait_for(self.client.async_audio(False), 2)
                    await asyncio.wait_for(self.client.async_stop_video(), 2)
                else:
                    payload = struct.pack("<3I", 0, 1, 0) + self.record[:8] + self.record[16:20] + self.client._token
                    await asyncio.wait_for(self.client.async_hub_request(794, payload, {795}), 2)
        except (VisionError, OSError, TimeoutError):
            pass
        finally:
            await self.client.async_close()

    async def close(self) -> None:
        self.ended = True
        if self.worker and not self.worker.done():
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
        await self.stop_transport()
        self.pcm.clear()
        self.jpeg = self.file = None

    def poll(self) -> dict:
        self.last_poll = time.monotonic()
        result = {
            "ended": self.ended,
            "error": self.error,
            "jpeg": base64.b64encode(self.jpeg).decode() if self.jpeg else None,
            "pcm": base64.b64encode(self.pcm).decode() if self.pcm else None,
        }
        self.jpeg = None
        self.pcm.clear()
        return result

    async def talk(self, enabled: bool) -> None:
        if self.record is not None or self.ended:
            raise ManagementError("Two-way talk requires an active live view")
        if not enabled:
            # T21/0228 accepts start-talk but does not reliably acknowledge its
            # stop command. Closing the authenticated session stops both media
            # directions and avoids leaving an uncertain microphone session.
            await self.close()
            self.ended = True
            self.talking = False
            return
        if self.talking != enabled:
            await self.client.async_talk(enabled)
            if self.ended or self._closing:
                await self.client.async_close()
                raise ManagementError("The camera session closed while starting the microphone")
            self.talking = enabled
            self._audio_sent = 0
            self._audio_start = time.monotonic()

    def send(self, encoded: str) -> None:
        if not self.talking or self.ended or len(encoded) > 6400:
            raise ManagementError("Start the microphone before sending audio")
        try:
            data = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise ManagementError("Invalid microphone audio") from None
        if not data or len(data) % 320:
            raise ManagementError("Invalid microphone audio frame size")
        if self._audio_sent + len(data) > (time.monotonic() - self._audio_start + 1) * 8000:
            raise ManagementError("Microphone audio exceeded the real-time rate")
        self._audio_sent += len(data)
        for offset in range(0, len(data), 320):
            self.client.send_audio(data[offset : offset + 320])


class VisionMedia:
    def __init__(self, manager) -> None:
        self.manager = manager
        self.recordings: dict[str, dict] = {}
        self.sessions: dict[str, MediaSession] = {}
        self._mutex = asyncio.Lock()

    async def list_recordings(self, lock_id: str) -> dict:
        lock = self.manager.lock(lock_id)
        zone = lock.get("tzId") or "UTC"
        now = datetime.now(ZoneInfo(zone))
        client = self.manager.coordinator._vision_client(lock)
        try:
            storage = await client.async_hub_request(33108, bytes(4), {33109})
            if len(storage) != 8:
                raise ManagementError("Invalid storage response")
            free, capacity = struct.unpack("<2I", storage)
            parts = await client.async_recording_list(camera_time(now - timedelta(days=7)), camera_time(now))
            entries = []
            total_expected = None
            for index, part in enumerate(parts):
                parsed, complete = parse_recordings(part, zone)
                total = struct.unpack_from("<I", part, 4)[0]
                if (
                    part[12] != index
                    or complete != (index == len(parts) - 1)
                    or total_expected is not None
                    and total != total_expected
                ):
                    raise ManagementError("The hub returned inconsistent recording list parts")
                total_expected = total
                entries.extend(parsed)
            if total_expected != len(entries) or len({e["id"] for e in entries}) != len(entries):
                raise ManagementError("The hub returned an incomplete recording list")
        except (VisionError, OSError, TimeoutError):
            raise ManagementError("Could not read the hub's recording storage") from None
        self.recordings[lock_id] = {
            "free": free,
            "total": capacity,
            "clips": entries,
            "message": "No recording storage is available on the hub."
            if capacity == 0
            else "No recordings in the past seven days."
            if not entries
            else "",
        }
        return self.manager.public(lock)

    async def start(self, lock_id: str, owner: str, clip_id: str | None = None, export: bool = False) -> dict:
        lock = self.manager.lock(lock_id)
        async with self._mutex:
            for token, session in list(self.sessions.items()):
                if session.ended:
                    await session.close()
                    del self.sessions[token]
            if self.sessions:
                raise ManagementError("Close the current live view or playback session first")
            record = None
            if clip_id:
                if not any(c["id"] == clip_id for c in self.recordings.get(lock_id, {}).get("clips", [])):
                    raise ManagementError("Refresh recordings and select a clip")
                record = bytes.fromhex(clip_id)
            if export and record is None:
                raise ManagementError("Select a recorded clip to export")
            session = MediaSession(lock, owner, record, export)
            await session.start()
            self.sessions[session.token] = session
            return {"session": session.token}

    def get(self, token: str, owner: str, lock_id: str) -> MediaSession:
        session = self.sessions.get(token)
        if session is None or session.owner != owner or session.lock_id != lock_id:
            raise ManagementError("This media session is unavailable")
        return session

    async def close(self) -> None:
        for session in self.sessions.values():
            await session.close()
        self.sessions.clear()
