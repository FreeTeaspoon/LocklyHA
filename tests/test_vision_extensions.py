"""Offline checks for access privacy, media clocks, codecs and bounded lifecycles."""

import asyncio
import base64
from fractions import Fraction
import io
import json
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

import av

from custom_components.lockly.api import des3_decrypt, des3_encrypt
from custom_components.lockly.vision import VisionClient, pack_control
from custom_components.lockly.vision_audio import ADPCMDecoder
from custom_components.lockly.vision_access import parse_fingerprints
from custom_components.lockly.vision_features import Credential, ManagementError, VisionManagement, build_set_pin
from custom_components.lockly.vision_media import MediaDecoder, MediaSession, VisionMedia, camera_time, parse_recordings
from custom_components.lockly.vision_sharing import build_ekey, _EKEY_KEY
from test_management import MC, UUID, NONCE, OWNER, GUEST
from datetime import datetime

LOCK = {
    "ID": UUID,
    "mc": MC,
    "p2pdid": "LOCKLYV-123456-ABCDE",
    "p2ppw": "test",
    "tz": "8.0",
    "fwv": "2.01.96",
    "na": "Test lock",
    "blename": "LOCKLYTEST",
}


class ProtocolTests(unittest.TestCase):
    def test_fingerprint_capacity_padding_delegation(self):
        self.assertEqual(
            [e["slot"] for e in parse_fingerprints(bytes([1, 99, 1, 2, 3, 4, 9]) + bytes(9))], [1, 2, 3, 4]
        )
        self.assertEqual(parse_fingerprints(bytes([1, 99, 129, 12]) + bytes(12)), [{"slot": 1, "delegated": True}])
        for invalid in (b"", bytes([1, 99, 1, 1, 11]) + bytes(11), bytes([2, 99, 0])):
            with self.assertRaises(ManagementError):
                parse_fingerprints(invalid)

    def test_vendor_adpcm_rounding_order_and_stream_state(self):
        decoder = ADPCMDecoder()
        self.assertEqual(struct.unpack("<4h", decoder.decode(bytes.fromhex("127f"))), (1, 4, 16, -14))
        stream = bytes(range(256)) * 3
        whole = ADPCMDecoder().decode(stream)
        chunked = ADPCMDecoder()
        self.assertEqual(whole, b"".join(chunked.decode(stream[i : i + 13]) for i in range(0, len(stream), 13)))
        media = MediaDecoder()
        self.assertEqual(len(media.decode(bytes(160), 83, True)), 640)

    def test_once_slot_requires_explicit_opt_in(self):
        entry = Credential(3, 49, "923457", b"\xff" * 10, "Once")
        with self.assertRaises(ManagementError):
            build_set_pin(MC, UUID, NONCE, entry)
        self.assertTrue(build_set_pin(MC, UUID, NONCE, entry, one_time=True))
        self.assertEqual(entry.public()["kind"], "one_time")

    def test_ekey_is_guest_scoped_and_valid_checksum(self):
        tp, tp2 = build_ekey(LOCK, GUEST)
        base = json.loads(des3_decrypt(_EKEY_KEY, tp))
        extra = json.loads(des3_decrypt(_EKEY_KEY, tp2))
        self.assertEqual(base["pwdid"], str(GUEST.slot))
        self.assertEqual(base["pwd"], GUEST.pin)
        self.assertNotIn("masterCode", base)
        self.assertNotEqual(
            base["aesKey"].lower(),
            __import__("custom_components.lockly.api", fromlist=["derive_aes_key"]).derive_aes_key(MC, UUID).hex(),
        )
        self.assertEqual(extra["permission"], 0)
        self.assertEqual(extra["hubPriviledge"], "N")
        self.assertTrue(all(not extra[k] for k in ("ad", "ap", "iotsecret", "hubid")))
        import hashlib

        checksum = "".join(
            ("1" if v else "0") if isinstance(v, bool) else str(v) for k, v in sorted(base.items()) if k != "enc"
        )
        self.assertEqual(hashlib.md5(checksum.encode()).hexdigest(), base["enc"])
        with self.assertRaises(ManagementError):
            build_ekey(LOCK, OWNER)
        with self.assertRaises(ManagementError):
            build_ekey(LOCK, Credential(3, 49, GUEST.pin, b"\xff" * 10, "Once"))

    def test_recording_list_strict_layout_and_date(self):
        record = camera_time(datetime(2026, 11, 21, 12, 30)) + struct.pack("<BBHII", 2, 0, 0, 7, 123)
        entries, final = parse_recordings(struct.pack("<3IBB2x", 0, 1, 1, 0, 1) + record, "Asia/Hong_Kong")
        self.assertTrue(final)
        self.assertEqual(entries[0]["id"], record.hex())
        self.assertTrue(entries[0]["time"].endswith("+08:00"))
        for invalid in (bytes(15), struct.pack("<3IBB2x", 0, 1, 2, 0, 1) + record):
            with self.assertRaises(ManagementError):
                parse_recordings(invalid, "UTC")

    def test_real_audio_decode_and_timestamped_mp4_export(self):
        encoder = av.CodecContext.create("libx264", "w")
        encoder.width, encoder.height, encoder.pix_fmt = 64, 64, "yuv420p"
        encoder.time_base = Fraction(1, 1000)
        encoder.options = {"preset": "ultrafast", "tune": "zerolatency", "bf": "0"}
        decoder = MediaDecoder(export=True)
        for pts in (0, 100, 250, 400):
            frame = av.VideoFrame(64, 64, "yuv420p")
            for plane in frame.planes:
                plane.update(bytes([100]) * plane.buffer_size)
            frame.pts, frame.time_base = pts, Fraction(1, 1000)
            packet = b"".join(bytes(p) for p in encoder.encode(frame))
            jpeg = decoder.decode(packet, 4, False, 1000 + pts)
            self.assertTrue(jpeg.startswith(b"\xff\xd8"))
            pcm = decoder.decode(bytes([0xD5]) * 800, 82, True, 1000 + pts)
            self.assertEqual(len(pcm), 1600)
        file = decoder.finish()
        with av.open(io.BytesIO(file)) as output:
            self.assertEqual(len(output.streams.video), 1)
            self.assertEqual(len(output.streams.audio), 1)
            frames = list(output.decode(video=0))
            times = [round(float(f.pts * f.time_base), 2) for f in frames]
            self.assertEqual(times, [0, 0.1, 0.25, 0.4])
        with av.open(io.BytesIO(file)) as output:
            self.assertGreater(sum(f.samples for f in output.decode(audio=0)), 0)


class WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_recording_response_collects_every_part(self):
        client = VisionClient(LOCK["p2pdid"], "test")
        client._send = Mock()
        client._authenticated = True
        client._reply = asyncio.get_running_loop().create_future()
        client._expected = {793}
        client._response_parts = []
        a = struct.pack("<3IBB2x", 0, 0, 0, 0, 0)
        b = struct.pack("<3IBB2x", 0, 0, 0, 1, 1)
        client._receive_data(b"\xd1\x00\x00\x00" + pack_control(793, a))
        self.assertFalse(client._reply.done())
        client._receive_data(b"\xd1\x00\x00\x01" + pack_control(793, b))
        self.assertEqual(client._reply.result(), [a, b])

    async def test_shares_do_not_publish_tokens_and_stale_writes_fail(self):
        from custom_components.lockly.capabilities import LockCapabilities

        c = SimpleNamespace(
            _get_lock=lambda _: LOCK, _caps_for=lambda _: LockCapabilities(lock_type=97), _vision_commands={}
        )
        manager = VisionManagement(c)
        access = manager.access
        raw = {"token": "sensitive-key", "pwdId": 7, "firstName": "Guest", "tempPwd": "secret"}
        access.cloud = AsyncMock(return_value={"tp": [raw]})
        result = await access.refresh_shares(UUID)
        self.assertNotIn("sensitive-key", json.dumps(result))
        self.assertNotIn('"secret"', json.dumps(result))
        entry = result["shares"][0]
        self.assertEqual((await access.reveal_share(UUID, entry["id"], entry["revision"]))["token"], raw["token"])
        with self.assertRaises(ManagementError):
            await access.revoke_share(UUID, entry["id"], "stale")
        self.assertTrue(all(call.args[0] == "getEkeyList" for call in access.cloud.call_args_list))

    async def test_enrollment_stop_uses_start_nonce_and_names_new_slot(self):
        from custom_components.lockly.capabilities import LockCapabilities

        c = SimpleNamespace(
            _get_lock=lambda _: LOCK,
            _caps_for=lambda _: LockCapabilities(lock_type=97),
            _vision_commands={},
            async_update_listeners=Mock(),
        )
        manager = VisionManagement(c)
        manager.nonce = AsyncMock(side_effect=[NONCE, "fresh-after-stop", "fresh-after-name"])
        from test_management import reply

        manager.exchange = AsyncMock(side_effect=[reply(0x14, b"\x01\x00"), reply(0x17, b"\x01\x00")])
        before = [{"slot": 1, "delegated": False, "name": "Original", "revision": "original"}]
        after = before + [{"slot": 2, "delegated": False, "name": "Fingerprint 2", "revision": "new"}]
        named = before + [{"slot": 2, "delegated": False, "name": "Test finger", "revision": "named"}]
        manager.access.read_fingers = AsyncMock(side_effect=[before, after, named])
        manager.access.cloud = AsyncMock(return_value={"cod": "200"})
        await manager.access.start_enrollment(UUID, "Test finger")
        await manager.access.finish_enrollment(UUID)
        self.assertEqual(manager.exchange.call_args_list[1].args, (LOCK, 0x17, NONCE, b"\x01"))
        request = manager.access.cloud.call_args.args[1]
        self.assertEqual((request["pid"], request["fn"], request["subadm"]), (2, "Test finger", "N"))
        self.assertFalse(manager.access.enrollment[UUID]["active"])
        self.assertEqual(before[0]["name"], "Original")
        await manager.access.close()

    async def test_create_key_decodes_token_and_saves_single_directory_row(self):
        from custom_components.lockly.capabilities import LockCapabilities

        c = SimpleNamespace(
            _get_lock=lambda _: LOCK,
            _caps_for=lambda _: LockCapabilities(lock_type=97),
            _vision_commands={},
            email="owner@example.invalid",
            password="test",
            des3_key=b"1234567890abcdefghijklmn",
        )
        manager = VisionManagement(c)
        manager.nonce = AsyncMock(return_value=NONCE)
        manager.read_credentials = AsyncMock(return_value=[OWNER, GUEST])
        manager.access.read_directory = AsyncMock(
            return_value=[{"pid": GUEST.slot, "dutype": "P", "fn": "Cloud name", "ln": "Surname", "subadm": "N"}]
        )
        original = {"token": "original", "pwdId": 8, "newName": "Original"}
        raw = [original]
        requests = []
        fail_save = False

        async def cloud(endpoint, request):
            requests.append((endpoint, request))
            if endpoint == "getEkeyList":
                return {"tp": list(raw)}
            if endpoint == "gentptoken":
                return {"token": des3_encrypt(c.des3_key, "new-token")}
            if endpoint == "du/save":
                if fail_save:
                    raise ManagementError("Uncertain profile save")
                self.assertEqual(len(request["usrarr"]), 1)
                self.assertEqual(request["usrarr"][0]["fn"], "Cloud name")
                self.assertEqual(request["usrarr"][0]["ln"], "Surname")
                self.assertIsInstance(request["pwData"]["token"], str)
                tp, _ = build_ekey(LOCK, GUEST)
                raw.append({"token": "new-token", "pwdId": "", "tempPwd": tp, "newName": "Test"})
                return {"cod": 200}
            if endpoint == "rmtoken":
                self.assertEqual(request["tp"], "new-token")
                return {"cod": 200}
            self.fail("Unexpected endpoint")

        manager.access.cloud = cloud
        result = await manager.access.create_share(UUID, GUEST.slot, manager.revision(GUEST))
        self.assertEqual(result["shares"][1]["slot"], GUEST.slot)
        self.assertNotIn("new-token", json.dumps(result))
        self.assertEqual(raw[0], original)
        self.assertEqual([e for e, _ in requests], ["getEkeyList", "gentptoken", "du/save", "getEkeyList"])

        manager.access.read_directory.return_value[0]["subadm"] = "Y"
        requests.clear()
        with self.assertRaisesRegex(ManagementError, "delegated"):
            await manager.access.create_share(UUID, GUEST.slot, manager.revision(GUEST))
        self.assertEqual(requests, [])
        manager.access.read_directory.return_value[0]["subadm"] = "N"
        raw[:] = [original]
        fail_save = True
        with self.assertRaisesRegex(ManagementError, "new eKey was revoked"):
            await manager.access.create_share(UUID, GUEST.slot, manager.revision(GUEST))
        self.assertEqual([e for e, _ in requests], ["getEkeyList", "gentptoken", "du/save", "rmtoken", "getEkeyList"])
        self.assertEqual(raw, [original])

    async def test_playback_audio_uses_header_codec(self):
        session = MediaSession(LOCK, "admin")
        session.playback(bytes(160), 428216306, 83, 1500)
        self.assertEqual(session.queue.get_nowait(), (bytes(160), 83, True, 1500))
        await session.close()

    async def test_export_is_not_ended_until_file_flush_finishes(self):
        session = MediaSession(LOCK, "admin", export=True)
        flushing, finish = threading.Event(), threading.Event()

        def flush():
            flushing.set()
            if not finish.wait(3):
                raise AssertionError("Export flush test timed out")
            return b"complete-mp4"

        session.decoder.finish = flush
        session.stop_transport = AsyncMock()
        session.playback(b"", 553649432, 0, 2000)
        session.worker = asyncio.create_task(session.run())
        try:
            self.assertTrue(await asyncio.to_thread(flushing.wait, 2))
            self.assertFalse(session.poll()["ended"])
            self.assertIsNone(session.file)
        finally:
            finish.set()
            await session.worker
        self.assertTrue(session.poll()["ended"])
        self.assertEqual(session.file, b"complete-mp4")
        await session.close()

    async def test_storage_capacity_is_not_replaced_by_recording_count(self):
        client = SimpleNamespace(
            async_hub_request=AsyncMock(return_value=struct.pack("<2I", 512, 1024)),
            async_recording_list=AsyncMock(return_value=[struct.pack("<3IBB2x", 0, 0, 0, 0, 1)]),
        )
        media = VisionMedia(
            SimpleNamespace(
                lock=lambda _: LOCK,
                coordinator=SimpleNamespace(_vision_client=lambda _: client),
                public=lambda _: {},
            )
        )
        await media.list_recordings(UUID)
        self.assertEqual(media.recordings[UUID]["total"], 1024)
        self.assertEqual(media.recordings[UUID]["clips"], [])

    async def test_transport_playback_preserves_timestamp_and_order(self):
        receive = Mock()
        client = VisionClient(LOCK["p2pdid"], "test", on_playback=receive)
        client._send = Mock()
        frame = struct.pack("<4I", 428216305, 5, 1234, 17) + b"video"
        client._receive_data(b"\xd1\x03\x00\x01" + frame[8:])
        receive.assert_not_called()
        client._receive_data(b"\xd1\x03\x00\x00" + frame[:8])
        receive.assert_called_once_with(b"video", 428216305, 17, 1234)

    async def test_media_owner_and_lock_binding_and_overflow(self):
        media = VisionMedia(None)
        session = MediaSession(LOCK, "admin", export=True)
        media.sessions[session.token] = session
        self.assertIs(media.get(session.token, "admin", UUID), session)
        for owner, lock_id in (("other", UUID), ("admin", "other")):
            with self.assertRaises(ManagementError):
                media.get(session.token, owner, lock_id)
        for _ in range(25):
            session.feed(b"frame", 4, False, 1)
        self.assertTrue(session.ended)
        self.assertIsNotNone(session.error)
        self.assertIsNone(session.file)
        await session.close()

    async def test_microphone_requires_start_and_enforces_frames(self):
        session = MediaSession(LOCK, "admin")
        with self.assertRaises(ManagementError):
            session.send(base64.b64encode(bytes(320)).decode())
        session.talking = True
        session._audio_start = __import__("time").monotonic()
        session.client.send_audio = Mock()
        session.send(base64.b64encode(bytes(320)).decode())
        session.client.send_audio.assert_called_once_with(bytes(320))
        with self.assertRaises(ManagementError):
            session.send(base64.b64encode(bytes(319)).decode())
        await session.close()


if __name__ == "__main__":
    unittest.main()
