from dataclasses import dataclass
from typing import Any

@dataclass
class JtechResponse:
    result: bool
    response: dict[str, Any]

@dataclass
class JtechLoginResponse(JtechResponse):
    token: str

@dataclass
class JtechNetworkResponse(JtechResponse):
    power: bool
    dhcp: bool
    ipaddress: str
    subnet: str
    gateway: str
    telnetport: int
    tcpport: int
    macaddress: str
    model: str
    hostname: str
    admin: bool  

@dataclass
class JtechStatusResponse(JtechResponse):
    power: bool
    dhcp: bool
    ipaddress: str
    subnet: str
    gateway: str
    telnetport: int
    tcpport: int
    macaddress: str
    model: str
    hostname: str
    admin: bool  

@dataclass
class JtechVideoStatusResponse(JtechResponse):
    power: bool
    selected_sources: list[int]
    source_names: list[str]
    output_names: list[str]
    output_cat_names: list[str]
    preset_names: list[str]

@dataclass
class JtechOutputStatusResponse(JtechResponse):
    power: bool
    selected_sources: list[int]
    selected_output_scalers: list[int]
    enabled_outputs: list[bool]
    enabled_cat_outputs: list[bool]
    connected_outputs: list[bool]
    connected_cat_outputs: list[bool]
    output_names: list[str]
    output_cat_names: list[str]

@dataclass
class JtechInputStatusResponse(JtechResponse):
    power: bool
    edid: list[int]
    active_sources: list[bool]
    source_names: list[str]

@dataclass
class JtechCECStatusResponse(JtechResponse):
    power: bool
    source_names: list[str]
    output_names: list[str]
    _current_source: list[int]
    _current_output: list[int]

@dataclass
class JtechSystemStatusResponse(JtechResponse):
    power: bool
    baudrate: int
    beep: bool
    lock: bool
    mode: int
    version: str
