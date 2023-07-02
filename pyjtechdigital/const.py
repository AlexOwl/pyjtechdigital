"""J-Tech Digital HDMI Matrix constants."""

from __future__ import annotations

from typing import Final

DEFAULT_LANGUAGE: Final = 0
DEFAULT_TIMEOUT: Final = 10
DEFAULT_TOKEN: Final = "ziming"

ATTR_RESULT: Final = "result"
ATTR_TOKEN: Final = "token"

ATTR_POWER: Final = "power"
ATTR_MODEL: Final = "model"
ATTR_VERSION: Final = "version"

ATTR_DHCP: Final = "dhcp"
ATTR_MAC: Final = "macaddress"
ATTR_HOSTNAME: Final = "hostname"
ATTR_IPADDRESS: Final = "ipaddress"
ATTR_SUBNET: Final = "subnet"
ATTR_GATEWAY: Final = "gateway"
ATTR_TELNETPORT: Final = "telnetport"
ATTR_TCPPORT: Final = "tcpport"

ATTR_BAUDRATE: Final = "baudrate"
ATTR_BEEP: Final = "beep"
ATTR_LOCK: Final = "lock"
ATTR_MODE: Final = "mode"

ATTR_USER: Final = "user"
ATTR_ADMIN: Final = "username"
ATTR_PASSWORD: Final = "password"
ATTR_PASSWORDNEW: Final = "newpassword"
ATTR_PASSWORDSURE: Final = "makesure"

ATTR_INPUT: Final = "input"
ATTR_SOURCE: Final = "source"
ATTR_INDEX: Final = "index"
ATTR_EDID: Final = "edid"
ATTR_SELECTED_SOURCES: Final = "allsource"
ATTR_ACTIVE_SOURCES: Final = "inactive"
ATTR_CURRENTSOURCE = "currentInput"

ATTR_OUTPUT: Final = "output"
ATTR_CONNECTED_OUTPUTS: Final = "allconnect"
ATTR_CONNECTED_CAT_OUTPUTS: Final = "allhdbtconnect"
ATTR_ENABLED_OUTPUTS: Final = "allout"
ATTR_ENABLED_CAT_OUTPUTS: Final = "allhdbtout"
ATTR_OUT: Final = "out"
ATTR_SELECTED_OUTPUT_SCALERS: Final = "allscaler"
ATTR_SELECT_OUTPUT_SCALER: Final = "scaler"
ATTR_CURRENTOUTPUT = "currentOutput"

ATTR_OBJECT: Final = "object"
ATTR_PORT: Final = "port"

ATTR_NAME: Final = "name"
ATTR_SOURCE_NAMES: Final = "allinputname"
ATTR_SOURCE_NAMES2: Final = "inname"
ATTR_OUTPUT_NAMES: Final = "alloutputname"
ATTR_OUTPUT_NAMES2: Final = "name"
ATTR_OUTPUT_CAT_NAMES: Final = "allhdbtoutputname"
ATTR_OUTPUT_CAT_NAMES2: Final = "hdbtname"
ATTR_PRESET_NAMES: Final = "allname"

ATTR_FACTORY: Final = "factory"
ATTR_REBOOT: Final = "reboot"

HEADER_CACHE_CONTROL: Final = "Cache-Control"
HEADER_CONNECTION: Final = "Connection"
HEADER_AUTHORIZATION: Final = "Authorization"
HEADER_SET_COOKIE: Final = "set-cookie"