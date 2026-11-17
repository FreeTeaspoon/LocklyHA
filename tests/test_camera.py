"""Offline camera decode, queue recovery and on-demand lifecycle checks."""
import asyncio
import io
import unittest
from fractions import Fraction
from types import SimpleNamespace
from unittest.mock import AsyncMock

import av

from custom_components.lockly.camera import VisionCamera, decode_jpeg


class CameraTests(unittest.IsolatedAsyncioTestCase):
    def camera(self):
        camera = VisionCamera({"ID": "test", "p2pdid": "LOCKLYV-000001-ABCDE", "p2ppw": "test"})
        async def executor(fn, *args):
            return fn(*args)
        camera.hass = SimpleNamespace(
            async_add_executor_job=executor,
            async_create_background_task=lambda coro, name: asyncio.create_task(coro, name=name),
        )
        camera._client = SimpleNamespace(
            async_start_video=AsyncMock(), async_stop_video=AsyncMock(),
            _disconnect=AsyncMock(), async_close=AsyncMock(),
        )
        return camera

    def test_decode_h264_as_browser_jpeg(self):
        encoder = av.CodecContext.create("libx264", "w")
        encoder.width, encoder.height = 64, 48
        encoder.pix_fmt = "yuv420p"
        encoder.time_base = Fraction(1, 20)
        encoder.options = {"preset": "ultrafast", "tune": "zerolatency"}
        frame = av.VideoFrame(64, 48, "yuv420p")
        for plane in frame.planes:
            plane.update(bytes([128]) * plane.buffer_size)
        encoded = b"".join(bytes(p) for p in encoder.encode(frame))
        decoder = av.CodecContext.create("h264", "r")
        jpeg_encoder = av.CodecContext.create("mjpeg", "w")
        jpeg_encoder.width, jpeg_encoder.height = 960, 540
        jpeg_encoder.pix_fmt = "yuvj420p"
        jpeg_encoder.time_base = Fraction(1, 20)
        jpeg = decode_jpeg(decoder, jpeg_encoder, encoded)
        self.assertIsNotNone(jpeg)
        with av.open(io.BytesIO(jpeg), format="mjpeg") as image:
            decoded = next(image.decode(video=0))
            self.assertEqual((decoded.width, decoded.height), (960, 540))

    async def test_overflow_waits_for_next_keyframe(self):
        camera = self.camera()
        camera._receive(b"predicted", 5, False)
        self.assertTrue(camera._queue.empty())
        camera._receive(b"keyframe", 5, True)
        for _ in range(7):
            camera._receive(b"predicted", 5, False)
        camera._receive(b"overflow", 5, False)
        self.assertTrue(camera._queue.empty())
        camera._receive(b"unusable", 5, False)
        camera._receive(b"new-keyframe", 5, True)
        self.assertEqual(camera._queue.get_nowait(), (b"new-keyframe", 5))

    async def test_idle_worker_stops_video_and_disconnects(self):
        camera = self.camera()
        camera._requested_at = 0
        await camera._run()
        camera._client.async_start_video.assert_awaited_once()
        camera._client.async_stop_video.assert_awaited_once()
        camera._client._disconnect.assert_awaited_once()

    async def test_multiple_viewers_share_worker_and_unload_cleans_up(self):
        camera = self.camera()
        images = [asyncio.create_task(camera.async_camera_image()) for _ in range(2)]
        for _ in range(4):
            await asyncio.sleep(0)
        worker = camera._worker
        self.assertIsNotNone(worker)
        camera._jpeg = b"image"
        import time
        camera._jpeg_at = time.monotonic()
        camera._ready.set()
        self.assertEqual(await asyncio.gather(*images), [b"image", b"image"])
        camera._client.async_start_video.assert_awaited_once()
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        camera._client.async_stop_video.assert_awaited_once()
        camera._client._disconnect.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
