__all__ = ["Site", "User"]
__version__ = "0.1.0"

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator
from enum import IntEnum

import sys
import os

try:
    from . import _windows
except ImportError:
    pass


class Domain(IntEnum):
    WINDOWS = sys.platform == "win32"
    MACOS = sys.platform == "darwin"


@dataclass(frozen=True)
class Site:

    name: str

    @staticmethod
    def __get(var: str, defaults: str) -> Iterator[Path]:
        paths = os.environ.get(var, defaults)
        return map(Path, paths.split(os.pathsep))

    @staticmethod
    def config_dirs() -> Iterator[Path]:
        if Domain.WINDOWS:
            yield _windows.FolderID.PROGRAM.path
            return
        yield from Site.__get("XDG_CONFIG_DIRS", "/etc/xdg")

    @staticmethod
    def data_dirs() -> Iterator[Path]:
        if Domain.WINDOWS:
            yield from Site.config_dirs()
            return
        yield from Site.__get("XDG_DATA_DIRS", "/usr/local/share:/usr/share")

    @property
    @lru_cache(maxsize=1)
    def data(self) -> Iterator[Path]:
        return [path.joinpath(self.name) for path in Site.data_dirs()]

    @property
    @lru_cache(maxsize=1)
    def config(self) -> Iterator[Path]:
        return [path.joinpath(self.name) for path in Site.config_dirs()]


@dataclass(frozen=True)
class User:
    name: str

    @staticmethod
    def __get(var: str, default: str) -> Path:
        return Path(os.environ.get(var, default)).expanduser()

    @staticmethod
    def config_home() -> Path:
        if Domain.WINDOWS:
            return _windows.FolderID.ROAMING.path
        elif Domain.MACOS:
            return User.data_home().joinpath("Application Support")
        return User.__get("XDG_CONFIG_HOME", "~/.config")

    @staticmethod
    def cache_home() -> Path:
        if Domain.WINDOWS:
            return _windows.FolderID.LOCAL.path
        elif Domain.MACOS:
            return User.data_home().joinpath("Caches")
        return User.__get("XDG_CACHE_HOME", "~/.cache")

    @staticmethod
    def data_home() -> Path:
        if Domain.WINDOWS:
            return _windows.FolderID.LOCAL.path
        elif Domain.MACOS:
            return Path("~/Library").expanduser()
        return User.__get("XDG_DATA_HOME", "~/.local/share")

    @property
    @lru_cache(maxsize=1)
    def config(self) -> Path:
        return User.config_home() / self.name

    @property
    @lru_cache(maxsize=1)
    def cache(self) -> Path:
        return User.cache_home() / self.name

    @property
    @lru_cache(maxsize=1)
    def data(self) -> Path:
        return User.data_home() / self.name
