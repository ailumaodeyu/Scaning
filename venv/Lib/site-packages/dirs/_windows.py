from ctypes.wintypes import DWORD, WORD, BYTE, HANDLE, LPWSTR
from ctypes import windll, Structure, POINTER, HRESULT, byref, c_int as Int, c_void_p as VoidPtr

from functools import lru_cache
from typing import get_type_hints

from pathlib import Path
from enum import Enum
from uuid import UUID

import struct


# TODO: Spin this out into its own package. We can greatly reduce the
# boilerplate in this package as a result.
def extern(dll, name=None):
    """Use type hints to declare and create types function pointers"""

    def wrapper(func):
        nonlocal name
        if not name:
            name = func.__name__
        fptr = dll[name]
        types = get_type_hints(func)
        restype = types.pop("return", Int)
        # This is a bizarre special case of the typing library
        if restype is type(None):  # noqa: E721
            restype = None
        fptr.restype = restype
        fptr.argtypes = list(types.values())
        return fptr

    return wrapper


class Pointer:
    def __class_getitem__(cls, typename):
        return POINTER(typename)


# TODO: Replace with decl.struct in the future.
class _GUID(Structure):
    _fields_ = [("x", DWORD), ("y", WORD), ("z", WORD), ("w", BYTE * 8)]

    def __init__(self, uuid: UUID):
        super().__init__()
        self.x, self.y, self.z, *rest = uuid.fields
        self.w[:] = [*rest[:2], *tuple(struct.pack("!Q", rest[2]))[2:8]]


PWSTR = Pointer[LPWSTR]


@extern(windll.ole32, "CoTaskMemFree")
def _CoTaskMemFree(_: VoidPtr) -> None:
    pass


@extern(windll.shell32, "SHGetKnownFolderPath")
def _GetFolderPath(rfid: Pointer[_GUID], flags: DWORD, token: HANDLE, path: PWSTR) -> HRESULT:
    pass


class FolderID(Enum):
    PROGRAM = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"
    ROAMING = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"
    LOCAL = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"

    def __init__(self, value: str):
        self.uuid = UUID(value)

    @property
    @lru_cache(maxsize=4)
    def path(self) -> Path:
        guid = _GUID(self.uuid)
        path = LPWSTR()
        if _GetFolderPath(byref(guid), 0, HANDLE(0), byref(path)) < 0:
            raise FileNotFoundError(f"Could not find path with GUID {self.uuid}")
        try:
            return Path(path.value)
        finally:
            _CoTaskMemFree(path)
