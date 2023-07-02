"""J-Tech Digital HDMI Matrix client."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from aiohttp import ClientError, ClientSession, CookieJar

from .const import (
    DEFAULT_LANGUAGE, DEFAULT_TIMEOUT, DEFAULT_TOKEN,
    ATTR_RESULT,
    ATTR_TOKEN,

    ATTR_DHCP,
    ATTR_POWER,
    ATTR_MODEL,
    ATTR_MAC,
    ATTR_HOSTNAME,
    ATTR_IPADDRESS,
    ATTR_SUBNET,
    ATTR_GATEWAY,
    ATTR_VERSION,
    ATTR_TELNETPORT,
    ATTR_TCPPORT,

    ATTR_SELECT_OUTPUT_SCALER,
    ATTR_EDID,
    ATTR_ACTIVE_SOURCES,
    ATTR_BAUDRATE,
    ATTR_BEEP,
    ATTR_LOCK,
    ATTR_MODE,
    ATTR_OBJECT,
    ATTR_PORT,
    ATTR_SOURCE,
    ATTR_INDEX,
    ATTR_OUTPUT,
    ATTR_SOURCE,
    ATTR_OUT,
    ATTR_NAME,

    ATTR_USER,
    ATTR_ADMIN,
    ATTR_PASSWORD,
    ATTR_PASSWORDNEW,
    ATTR_PASSWORDSURE,

    ATTR_FACTORY,
    ATTR_REBOOT,

    ATTR_CURRENTSOURCE,
    ATTR_CURRENTOUTPUT,

    ATTR_SELECTED_SOURCES,
    ATTR_SELECTED_OUTPUT_SCALERS,
    ATTR_ENABLED_OUTPUTS,
    ATTR_ENABLED_CAT_OUTPUTS,
    ATTR_CONNECTED_OUTPUTS,
    ATTR_CONNECTED_CAT_OUTPUTS,

    ATTR_PRESET_NAMES,
    ATTR_SOURCE_NAMES,
    ATTR_SOURCE_NAMES2,
    ATTR_OUTPUT_NAMES,
    ATTR_OUTPUT_NAMES2,
    ATTR_OUTPUT_CAT_NAMES,
    ATTR_OUTPUT_CAT_NAMES2,
    HEADER_CACHE_CONTROL, HEADER_CONNECTION, HEADER_AUTHORIZATION, HEADER_SET_COOKIE,
)

from .responses import JtechResponse, JtechLoginResponse, JtechNetworkResponse, JtechStatusResponse, JtechVideoStatusResponse, JtechOutputStatusResponse, JtechInputStatusResponse, JtechCECStatusResponse, JtechSystemStatusResponse
from .exceptions import JtechError, JtechAuthError, JtechNotSupported, JtechConnectionError, JtechConnectionTimeout, JtechInvalidSource, JtechInvalidOutput, JtechOptionError

_LOGGER = logging.getLogger(__name__)

class JtechClient:
    """Represent a J-Tech Digital HDMI Matrix Client."""

    def __init__(
        self, host: str, session: ClientSession | None = None
    ) -> None:
        """Initialize the device."""
        self.host = host
        self._session = session
        self._token: str | None = None
        self._sources_count: int | None = None
        self._outputs_count: int | None = None



    async def connect(
        self,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        """Open connection."""
        _LOGGER.debug(
            "Connect with user: %s, password: %s",
            user,
            password
        )

        if user is not None:
            assert password is not None
            login_response = await self.login(user, password)

            if not (login_response and login_response.result):
                raise JtechAuthError
            self._token = login_response.token or DEFAULT_TOKEN

        else:
            if self._session is not None:
                self._token = None
                self._session.cookie_jar.clear()

        video_status = await self.get_video_status()
        if not video_status:
            raise JtechNotSupported

        self._sources_count = len(video_status.source_names)
        self._outputs_count = len(video_status.output_names)

        _LOGGER.debug("Connected")

    async def disconnect(self,) -> None:
        """Close connection."""
        if self._session:
            await self._session.close()
        self._token = None
        self._session = None
        self._sources_count = None
        self._outputs_count = None



    async def send_rest_req(
        self,
        method: str,
        params: Any = None,
        headers: dict[str, Any] | None = None,
        language: str = DEFAULT_LANGUAGE,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Any:
        """Send REST request to device."""
        url = f"http://{self.host}/cgi-bin/instr"
        params = params if isinstance(params, dict) else {}
        data = {
            "comhead": method,
            "language": language,
            **params,
        }

        return await self.send_req(url=url, data=data, headers=headers, json=True, timeout=timeout)

    async def send_rest_quick(self, *args: Any, **kwargs: Any) -> bool:
        """Send and quick check REST request to device."""
        result = await self.send_rest_req(*args, **kwargs)
        return JtechResponse(
            bool(result.get(ATTR_RESULT)),
            result
        )

    async def send_req(
        self,
        url: str,
        data: Any = None,
        headers: dict[str, Any] | None = None,
        json: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Any:
        """Send HTTP request."""
        result = {} if json else False

        if self._session is None:
            self._session = ClientSession(
                cookie_jar=CookieJar(unsafe=True, quote_cookie=False)
            )

        if headers is None:
            headers = {}

        headers[HEADER_CACHE_CONTROL] = "no-cache"
        headers[HEADER_CONNECTION] = "keep-alive"
        if self._token:
            headers[HEADER_AUTHORIZATION] = f"Bearer {self._token}"

        _LOGGER.debug("Request %s, data: %s, headers: %s", url, data, headers)

        try:
            if json:
                response = await self._session.post(
                    url, json=data, headers=headers, timeout=timeout
                )
            else:
                response = await self._session.post(
                    url, data=data, headers=headers, timeout=timeout
                )

            _LOGGER.debug("Response status: %s", response.status)

            cookies = response.headers.getall(HEADER_SET_COOKIE, None)
            if cookies:
                normalized_cookies = normalize_cookies(cookies)
                self._session.cookie_jar.update_cookies(normalized_cookies)

            if response.status == 200:
                result = await response.json(content_type=None) if json else True
                _LOGGER.debug("Response result: %s", result)
        except ClientError as err:
            _LOGGER.debug("Request error %s", err)
            raise JtechConnectionError from err
        except ConnectionError as err:
            _LOGGER.debug("Connection error %s", err)
            raise JtechConnectionError from err
        except asyncio.exceptions.TimeoutError as err:
            _LOGGER.debug("Request timeout %s", err)
            raise JtechConnectionTimeout from err

        return result



    async def get_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get status")
        #"comhead": "get status",
        #"power": 1,
        #"model": "HDP-MXB44D70M",
        #"version": "V1.08.08",
        #"hostname": "IP-module-8DA03",
        #"ipaddress": "10.69.30.30",
        #"subnet": "255.255.255.0",
        #"gateway": "10.69.30.1",
        #"macaddress": "6C:DF:FB:08:DA:03"
        return JtechStatusResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            result.get(ATTR_MODEL),
            result.get(ATTR_VERSION),
            result.get(ATTR_HOSTNAME),
            result.get(ATTR_IPADDRESS),
            result.get(ATTR_SUBNET),
            result.get(ATTR_GATEWAY),
            result.get(ATTR_MAC),
        )

    async def login(self, user: str, password: str,) -> None:
        result = await self.send_rest_req(
            "login",
            {
                ATTR_USER: user,
                ATTR_PASSWORD: password,
            },
        )

        return JtechLoginResponse(
            bool(result.get(ATTR_RESULT)),
            result,
            result.get(ATTR_TOKEN)
        )

    async def set_power(self, power: bool,) -> bool:
        return await self.send_rest_quick(
            "set poweronoff",
            {
                ATTR_POWER: int(power),
            },
        )



    async def get_video_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get video status")
        #"power": 1,
        #"allsource": [1, 1, 1, 1],
        #"allinputname": ["Apple TV", "PlayStation", "Nintendo", "Input4"],
        #"alloutputname": ["L Projector", "L TV", "U TV", "Output4"],
        #"allhdbtoutputname": ["catoutput1", "catoutput2", "catoutput3", "catoutput4"],
        #"allname": ["preset1", "preset2", "preset3", "preset4"]
        return JtechVideoStatusResponse(
            True,
            result,
            result.get(ATTR_SELECTED_SOURCES),
            result.get(ATTR_SOURCE_NAMES),
            result.get(ATTR_OUTPUT_NAMES),
            result.get(ATTR_OUTPUT_CAT_NAMES),
            result.get(ATTR_PRESET_NAMES),
        )

    async def set_video_source(self, output: int, source: int,) -> bool:
        self.validate_output(output)
        self.validate_source(source)
        return await self.send_rest_quick(
            "video switch",
            {
                ATTR_SOURCE: [
                    output, 
                    source,
                ],
            },
        )

    async def set_preset_name(self, preset: int, preset_name: str,) -> bool:
        return await self.send_rest_quick(
            "preset name",
            {
                ATTR_INPUT: preset,
                ATTR_NAME: preset_name,
            },
        )

    async def preset_set(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset set",
            {
                ATTR_INDEX: preset,
            },
        )
    
    async def preset_save(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset save",
            {
                ATTR_INDEX: preset,
            },
        )

    async def preset_clear(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset clear",
            {
                ATTR_INDEX: preset,
            },
        )



    async def get_source_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get input status")
        #"comhead": "get input status",
        #"power": 1,
        #"edid": [16, 19, 19, 19],
        #"inactive": [1, 0, 0, 0],
        #"inname": ["Apple TV", "PlayStation", "Nintendo", "Input4"]
        return JtechInputStatusResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            result.get(ATTR_EDID, []),
            map(bool, result.get(ATTR_ACTIVE_SOURCES, [])),
            result.get(ATTR_SOURCE_NAMES2, []),
        )

    async def set_source_names(self, source_names: list[str],) -> bool:
        self.validate_source(source_names)
        return await self.send_rest_quick(
            "set input name",
            {
                ATTR_INPUT: source_names,
            },
        )

    #1080P,Stereo Audio 2.0 - 0
    #1080P,Dolby/DTS 5.1
    #1080P,HD Audio 7.1
    #1080I,Stereo Audio 2.0
    #1080I,Dolby/DTS 5.1
    #1080I,HD Audio 7.1
    #3D,Stereo Audio 2.0
    #3D,Dolby/DTS 5.1
    #3D,HD Audio 7.1
    #4K2K30_444,Stereo Audio 2.0
    #4K2K30_444,Dolby/DTS 5.1
    #4K2K30_444,HD Audio 7.1
    #4K2K60_420,Stereo Audio 2.0
    #4K2K60_420,Dolby/DTS 5.1
    #4K2K60_420,HD Audio 7.1
    #4K2K60_444,Stereo Audio 2.0
    #4K2K60_444,Dolby/DTS 5.1
    #4K2K60_444,HD Audio 7.1
    #4K2K60_444,Stereo Audio 2.0 HDR
    #4K2K60_444,Dolby/DTS 5.1 HDR
    #4K2K60_444,HD Audio 7.1 HDR
    #User Define1
    #User Define2
    #COPY_FROM_HDMI_1
    #COPY_FROM_HDMI_2
    #COPY_FROM_HDMI_3
    #COPY_FROM_HDMI_4
    #COPY_FROM_CAT_1
    #COPY_FROM_CAT_2
    #COPY_FROM_CAT_3
    #COPY_FROM_CAT_4
    async def set_source_edid(self, source: int, edid: int,) -> bool:
        self.validate_source(source)
        return await self.send_rest_quick(
            "set edid",
            {
                ATTR_EDID: [
                    source, 
                    edid,
                ],
            },
        )

    #TODO: async def set_user_edid(self,)
    #TODO: async def download_edid(self,)



    async def get_output_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get output status")
        #"comhead": "get output status",
        #"power": 1,
        #"allsource": [1, 1, 1, 1],
        #"allscaler": [0, 0, 0, 0],
        #"allout": [0, 0, 0, 0],
        #"allhdbtout": [1, 1, 1, 1],
        #"allconnect": [1, 1, 1, 1],
        #"allhdbtconnect": [0, 1, 1, 0],
        #"name": ["L Projector", "L TV", "U TV", "Output4"],
        #"hdbtname": ["catoutput1", "catoutput2", "catoutput3", "catoutput4"]
        return JtechOutputStatusResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            result.get(ATTR_SELECTED_SOURCES, []),
            result.get(ATTR_SELECTED_OUTPUT_SCALERS, []),
            map(bool, result.get(ATTR_ENABLED_OUTPUTS, [])),
            map(bool, result.get(ATTR_ENABLED_CAT_OUTPUTS, [])),
            map(bool, result.get(ATTR_CONNECTED_OUTPUTS, [])),
            map(bool, result.get(ATTR_CONNECTED_CAT_OUTPUTS, [])),
            result.get(ATTR_OUTPUT_NAMES2, []),
            result.get(ATTR_OUTPUT_CAT_NAMES2, []),
        )

    async def set_output_names(self, output_names: list[str],) -> bool:
        self.validate_output(output_names)
        return await self.send_rest_quick(
            "set output name",
            {
                ATTR_OUTPUT: output_names,
            },
        )

    async def set_output_cat_names(self, output_names: list[str],) -> bool:
        self.validate_output(output_names)
        return await self.send_rest_quick(
            "set output name",
            {
                ATTR_OUTPUT_CAT_NAMES2: output_names,
            },
        )

    #scaler: 0 - Bypass, 1 - 4K to 1080p, 3 - Auto
    async def set_output_scaler(self, output: int, scaler: int,) -> bool:
        self.validate_output(output)
        return await self.send_rest_quick(
            "video scaler",
            {
                ATTR_SELECT_OUTPUT_SCALER: [
                    output, 
                    scaler,
                ],
            },
        )

    async def set_output_stream(self, output: int, stream: bool,) -> bool:
        self.validate_output(output)
        return await self.send_rest_quick(
            "tx stream",
            {
                ATTR_OUT: [
                    output, #hdmi 1-4
                    int(stream),
                ],
            },
        )

    async def set_output_cat_stream(self, output: int, stream: bool,) -> bool:
        self.validate_output(output)
        return await self.send_rest_quick(
            "tx stream",
            {
                ATTR_OUT: [
                    int(self._outputs_count + output), #cat 5-8
                    int(stream),
                ],
            },
        )
    


    async def get_cec_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get cec status")
        #"power": 1,
        #"allinputname": ["Apple TV1", "PlayStation", "Nintendo", "Input4"],
        #"alloutputname": ["L Projector", "L TV", "U TV", "Output4"],
        #"currentInput": [0, 0, 0, 0],
        #"currentOutput": [0, 0, 0, 0]
        return JtechCECStatusResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            result.get(ATTR_SOURCE_NAMES),
            result.get(ATTR_OUTPUT_NAMES),
            result.get(ATTR_CURRENTSOURCE),
            result.get(ATTR_CURRENTOUTPUT),
        )

    #command: 1 - turnon, 2 - turnoff, 3 - keyup, 4 - keyleft, 5 - center, 6 - keyright, 7 - menu, 8 - keydown, 9 - back, 10 - prev, 11 - play, 12 - next, 13 - rewind, 14 - pause, 15 - forward, 16 - stop, 17 - mute, 18 - volumedown, 19 - volumeup
    async def send_cec_sources(self, sources: list[bool], command: int,) -> bool: 
        self.validate_source(sources)
        return await self.send_rest_quick(
            "cec command",
            {
                ATTR_OBJECT: 0,
                ATTR_PORT: map(int, sources),
                ATTR_INDEX: command,
            },
        )

    async def send_cec_source(self, source: int, command: int,) -> bool: 
        self.validate_source(source)
        sources = list(map(lambda i: i == source, range(1, self._sources_count+1)))
        return await self.send_cec_sources(sources, command)

    #command: 0 - turnon, 1 - turnoff, 2 - mute, 3 - volumedown, 4 - volumeup, 5 - source
    async def send_cec_outputs(self, outputs: list[bool], command: int,) -> bool: #command:
        self.validate_output(outputs)
        return await self.send_rest_quick(
            "cec command",
            {
                ATTR_OBJECT: 1,
                ATTR_PORT: map(int, outputs),
                ATTR_INDEX: command,
            },
        )

    async def send_cec_output(self, output: int, command: int,) -> bool: 
        self.validate_output(output)
        sources = list(map(lambda i: i == source, range(1, self._outputs_count+1)))
        return await self.send_cec_outputs(sources, command)



    async def get_network(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get network")
        #"comhead": "get network",
        #"power": 1,
        #"dhcp": 1,
        #"ipaddress": "10.69.30.30",
        #"subnet": "255.255.255.0",
        #"gateway": "10.69.30.1",
        #"telnetport": 23,
        #"tcpport": 8000,
        #"macaddress": "6C:DF:FB:08:DA:03",
        #"model": "HDP-MXB44D70M",
        #"hostname": "IP-module-8DA03",
        #"username": 1    
        return JtechNetworkResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            bool(result.get(ATTR_DHCP)),
            result.get(ATTR_IPADDRESS),
            result.get(ATTR_SUBNET),
            result.get(ATTR_GATEWAY),
            result.get(ATTR_TELNETPORT),
            result.get(ATTR_TCPPORT),
            result.get(ATTR_MAC),
            result.get(ATTR_MODEL),
            result.get(ATTR_HOSTNAME),
            bool(result.get(ATTR_ADMIN)),
        )

    async def set_network(self, dhcp: bool, ipaddress: str, subnet: str, gateway: str, telnetport: int, tcpport: int, macaddress: str, model: str, hostname: str, admin: bool) -> bool:
        return await self.send_rest_quick(
            "set network",
            {
                ATTR_DHCP: int(dhcp),
                ATTR_IPADDRESS: ipaddress,
                ATTR_SUBNET: subnet,
                ATTR_GATEWAY: gateway,
                ATTR_TELNETPORT: telnetport,
                ATTR_TCPPORT: tcpport,
                ATTR_MAC: macaddress,
                ATTR_MODEL: model,
                ATTR_HOSTNAME: hostname,
                ATTR_ADMIN: int(admin)
            }
        ) 

    async def set_network_defaults(self,) -> bool:
        return await self.send_rest_quick(
            "set defaults network",
        )

    async def set_password(self, user: str, password: str, password_new: str,) -> bool: #modify password
        return await self.send_rest_quick(
            "modify password",
            {
                ATTR_USER: user,
                ATTR_PASSWORD: password,
                ATTR_PASSWORDNEW: password_new,
                ATTR_PASSWORDSURE: password_new,
            },
        )

 

    async def get_system_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get system status")
        #"power": 1,
        #"baudrate": 6,
        #"beep": 0,
        #"lock": 0,
        #"mode": 1,
        #"version": "V1.08.08"
        return JtechSystemStatusResponse(
            True,
            result,
            bool(result.get(ATTR_POWER)),
            result.get(ATTR_BAUDRATE),
            bool(result.get(ATTR_BEEP)),
            bool(result.get(ATTR_LOCK)),
            result.get(ATTR_MODE),
            result.get(ATTR_VERSION),
        )

    async def set_panel_lock(self, lock: bool,) -> bool:
        return await self.send_rest_quick(
            "set panel lock",
            {
                ATTR_LOCK: int(lock),
            },
        )

    async def set_beep(self, beep: bool,) -> bool:
        return await self.send_rest_quick(
            "set beep",
            {
                ATTR_BEEP: int(beep),
            },
        )

    # 1 - 4800, 2 - 9600, 3 - 19200, 4 - 38400, 5 - 57600, 6 - 115200
    async def set_baudrate(self, baudrate: int,) -> bool:
        return await self.send_rest_quick(
            "set baudrate",
            {
                ATTR_BAUDRATE: baudrate,
            },
        )

    async def set_factory(self, factory: bool = True,) -> bool:
        return await self.send_rest_quick(
            "set factory",
            {
                ATTR_FACTORY: int(factory),
            },
        )

    async def reboot(self, reboot: bool = True,) -> bool:
        return await self.send_rest_quick(
            "reboot",
            {
                ATTR_REBOOT: int(reboot),
            },
        )



    def validate_source(source: int | list,) -> None:
        if not ((isinstance(source, list) and len(source) == self._sources_count) or (source >= 1 and source <= self._sources_count)):
            raise JtechInvalidSource

    def validate_output(output: int | list,) -> None:
        if not ((isinstance(output, list) and len(output) == self._outputs_count) or (output >= 1 and output <= self._outputs_count)):
            raise JtechInvalidOutput



    #TODO: async def set_tx_hdcp(self,)
    #TODO: async def set_arc(self,)

    #TODO: set tgp

    #TODO: cgi-bin/query?_= + (new Date).getTime()

    #TODO: cgi-bin/getinfo
    #version = 20.01
    #firmware = 8.03.03_1.00.5

    #proto = dhcp
    #ipaddr = 192.168.1.100
    #netmask = 255.255.255.0
    #macaddr = 6C:DF:FB:08:DA:03

    #use_smart_pack = 0
    #use_proto_size = 13 #