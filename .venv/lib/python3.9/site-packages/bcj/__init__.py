from typing import Union

try:
    from importlib.metadata import PackageNotFoundError  # type: ignore
    from importlib.metadata import version  # type: ignore
except ImportError:
    from importlib_metadata import PackageNotFoundError  # type: ignore
    from importlib_metadata import version  # type: ignore

__copyright__ = 'Copyright (C) 2020,2021 Hiroshi Miura'

try:
    __version__ = version(__name__)
except PackageNotFoundError:  # pragma: no-cover
    # package is not installed
    __version__ = "unknown"

from _bcj import ffi, lib  # type: ignore


class BCJFilter:

    def __init__(self, func, readahead: int, is_encoder: bool, stream_size: int = 0):
        self.is_encoder = is_encoder
        self.buffer = bytearray()
        self.state = ffi.new('UInt32 *', 0)
        self.ip = 0
        #
        self._readahead = readahead
        self.stream_size: int = stream_size
        self.method = func

    def arm_code(self, buf, size):
        return lib.ARM_Convert(buf, size, self.ip, self.is_encoder)

    def armt_code(self, buf, size):
        return lib.ARMT_Convert(buf, size, self.ip, self.is_encoder)

    def sparc_code(self, buf, size):
        return lib.SPARC_Convert(buf, size, self.ip, self.is_encoder)

    def ppc_code(self, buf, size):
        return lib.PPC_Convert(buf, size, self.ip, self.is_encoder)

    def x86_code(self, buf, size):
        return lib.x86_Convert(buf, size, self.ip, self.state, self.is_encoder)

    def ia64_code(self, buf, size):
        return lib.IA64_Convert(buf, size, self.ip, self.is_encoder)

    def decode(self, data: Union[bytes, bytearray, memoryview]) -> bytes:
        self.buffer.extend(data)
        size = len(self.buffer)
        buf = ffi.from_buffer(self.buffer, require_writable=True)
        out_size = self.method(buf, size)
        result = ffi.buffer(buf, out_size)
        self.ip += out_size
        self.buffer = self.buffer[out_size:]
        if self.ip >= self.stream_size - self._readahead:
            return bytes(result) + self.buffer[-self._readahead:]
        return bytes(result)

    def encode(self, data: Union[bytes, bytearray, memoryview]) -> bytes:
        self.buffer.extend(data)
        size = len(self.buffer)
        buf = ffi.from_buffer(self.buffer, require_writable=True)
        out_size = self.method(buf, size)
        result = ffi.buffer(buf, out_size)
        self.ip += out_size
        self.buffer = self.buffer[out_size:]
        return bytes(result)

    def flush(self):
        return bytes(self.buffer)


class BCJDecoder(BCJFilter):

    def __init__(self, size: int):
        super().__init__(self.x86_code, 5, False, size)


class BCJEncoder(BCJFilter):

    def __init__(self):
        super().__init__(self.x86_code, 5, True)


class SparcDecoder(BCJFilter):

    def __init__(self, size: int):
        super().__init__(self.sparc_code, 4, False, size)


class SparcEncoder(BCJFilter):

    def __init__(self):
        super().__init__(self.sparc_code, 4, True)


class PpcDecoder(BCJFilter):

    def __init__(self, size: int):
        super().__init__(self.ppc_code, 4, False, size)


class PpcEncoder(BCJFilter):

    def __init__(self):
        super().__init__(self.ppc_code, 4, True)


class ArmtDecoder(BCJFilter):

    def __init__(self, size: int):
        super().__init__(self.armt_code, 4, False, size)


class ArmtEncoder(BCJFilter):

    def __init__(self):
        super().__init__(self.armt_code, 4, True)


class ArmDecoder(BCJFilter):

    def __init__(self, size: int):
        super().__init__(self.arm_code, 4, False, size)


class ArmEncoder(BCJFilter):

    def __init__(self):
        super().__init__(self.arm_code, 4, True)
