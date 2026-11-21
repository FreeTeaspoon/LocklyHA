"""The camera's headerless ADPCM stream, matching libadPcm.so adpcmDec."""
import struct

_STEP = (
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55,
    60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411,
    1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
    5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500,
    20350, 22385, 24623, 27086, 29794, 32767,
)
_INDEX = (-1, -1, -1, -1, 2, 4, 6, 8)


class ADPCMDecoder:
    """High nibble first; predictor and step index persist across packets."""
    def __init__(self) -> None:
        self.sample = self.index = 0

    def decode(self, data: bytes) -> bytes:
        result = bytearray(len(data) * 4)
        offset = 0
        for value in data:
            for nibble in (value >> 4, value & 15):
                magnitude = nibble & 7
                step = _STEP[self.index]
                # The vendor multiplies before division, unlike IMA's common
                # per-bit shift implementation. Preserve its integer rounding.
                delta = step * magnitude // 4 + step // 8
                self.sample = max(-32768, min(32767, self.sample + (-delta if nibble & 8 else delta)))
                struct.pack_into("<h", result, offset, self.sample)
                offset += 2
                self.index = max(0, min(88, self.index + _INDEX[magnitude]))
        return bytes(result)
