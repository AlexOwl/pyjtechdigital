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
class JtechStatusResponse(JtechResponse):
    power: bool
    model: str
    version: str
    hostname: str
    ipaddress: str
    subnet: str
    gateway: str
    macaddress: str  

@dataclass
class JtechVideoStatusResponse(JtechResponse):
    power: bool
    selected_sources: list[int]
    source_names: list[str]
    output_names: list[str]
    output_cat_names: list[str]
    preset_names: list[str]

@dataclass
class JtechInputStatusResponse(JtechResponse):
    power: bool
    edid_indexes: list[int]
    active_sources: list[bool]
    source_names: list[str]

# must be like this, so probably some user will have different behaviour
# waiting an issue :)
#allarc: [0, 0, 0, 0, 0, 0, 0, 0],
#allconnect: [0, 0, 0, 0, 0, 0, 0, 0],
#allhdbtarc: [0, 0, 0, 0, 0, 0, 0, 0],
#allhdbtconnect: [0, 0, 0, 0, 0, 0, 0, 0],
#allhdbthdcp: [0, 0, 0, 0, 0, 0, 0, 0],
#allhdbtout: [1, 1, 1, 1, 1, 1, 1, 1],
#allhdbtscaler: [0, 0, 0, 0, 0, 0, 0, 0],
#allhdcp: [0, 0, 0, 0, 0, 0, 0, 0],
#allout: [1, 1, 1, 1, 1, 1, 1, 1],
#allscaler: [0, 0, 0, 0, 0, 0, 0, 0],
#allsource: [1, 1, 1, 1, 1, 1, 1, 1],
#name: ["OUTPUT1", "OUTPUT2", "OUTPUT3", "OUTPUT4"],
#hdbtname: ["OUTPUT1", "OUTPUT2", "OUTPUT3", "OUTPUT4"]

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
class JtechCECStatusResponse(JtechResponse):
    power: bool
    source_names: list[str]
    output_names: list[str]
    selected_cec_sources: list[int]
    selected_cec_outputs: list[int]

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
class JtechSystemStatusResponse(JtechResponse):
    power: bool
    baudrate_index: int
    beep: bool
    lock: bool
    mode: int
    version: str

@dataclass
class JtechEdidResponse(JtechResponse):
    index: int
    edid: str

@dataclass
class JtechWebDetailsResponse(JtechResponse):
    title: str