"""Python library for remote control of J-Tech Digital HDMI Matrix."""

from .client import JtechClient
from .exceptions import JtechError, JtechAuthError, JtechNotSupported, JtechConnectionError, JtechConnectionTimeout, JtechOptionError

__version__ = "0.1.1"