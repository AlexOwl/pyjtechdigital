"""J-Tech Digital HDMI Matrix client."""

from __future__ import annotations

import asyncio
import logging
import socket
from contextlib import suppress
from datetime import datetime, timedelta
from types import TracebackType
from typing import Any

from aiohttp import ClientError, ClientSession, CookieJar

from .const import DEFAULT_LANGUAGE, DEFAULT_TIMEOUT, DEFAULT_TOKEN

from .exceptions import JtechError, JtechAuthError, JtechNotSupported, JtechConnectionError, JtechConnectionTimeout, JtechOptionError

_LOGGER = logging.getLogger(__name__)

class JtechClient:
    """Represent a Bravia Client."""

    def __init__(
        self, host: str, session: ClientSession | None = None
    ) -> None:
        """Initialize the device."""
        self.host = host
        self._session = session
        self._token: str | None = None
        self._inputs_count: int | None = None
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

            resp = await self.login(user, password)
            if not resp:
                raise JtechAuthError
        else:
            if self._session is not None:
                self._token = None
                self._session.cookie_jar.clear()

        video_status = await self.get_output_status()
        if not video_status:
            raise JtechNotSupported

        self._inputs_count = len(video_status.allinputname)
        self._outputs_count = len(video_status.alloutputname)

        _LOGGER.debug("Connected")

    async def disconnect(self,) -> None:
        """Close connection."""
        if self._session:
            await self._session.close()
        self._token = None
        self._session = None
        self._inputs_count = None
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

        resp = await self.send_req(
            url=url, data=data, headers=headers, json=True, timeout=timeout
        )

        return resp

    async def send_rest_quick(self, *args: Any, **kwargs: Any) -> bool:
        """Send and quick check REST request to device."""
        resp = await self.send_rest_req(*args, **kwargs)
        return bool("result" in resp)

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

        headers["Cache-Control"] = "no-cache"
        headers["Connection"] = "keep-alive"
        headers["Authorization"] = f"Bearer {self._token}"

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

            cookies = response.headers.getall("set-cookie", None)
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

    async def login(self, user: str, password: str,) -> None:
        result = await self.send_rest_req(
            "login",
            {
                "user": user,
                "password": password,
            },
        )
        if not result.get("result", 0):
            raise JtechAuthError

        self._token = result.get("token", DEFAULT_TOKEN)

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
        return result

    async def set_network(self, use_dhcp: bool, ipaddress: str, subnet: str, gateway: str, telnetport: int, tcpport: int, macaddress: str, model: str, hostname: str, username_admin: bool) -> bool:
        result = await self.send_rest_quick(
            "set network",
            {
                "dhcp": int(use_dhcp),
                "ipaddress": ipaddress,
                "subnet": subnet,
                "gateway": gateway,
                "telnetport": telnetport,
                "tcpport": tcpport,
                "macaddress": macaddress,
                "model": model,
                "hostname": hostname,
                "username": int(username_admin)
            }
        )  
        return result

    async def set_network_defaults(self,) -> bool:
        return await self.send_rest_quick(
            "set defaults network",
        )

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
        return result

    async def get_video_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get video status")
        #"power": 1,
	    #"allsource": [1, 1, 1, 1],
	    #"allinputname": ["Apple TV", "PlayStation", "Nintendo", "Input4"],
	    #"alloutputname": ["L Projector", "L TV", "U TV", "Output4"],
	    #"allhdbtoutputname": ["catoutput1", "catoutput2", "catoutput3", "catoutput4"],
	    #"allname": ["preset1", "preset2", "preset3", "preset4"]
        return result

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
        return result

    async def get_input_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get input status")
        #"comhead": "get input status",
	    #"power": 1,
	    #"edid": [16, 19, 19, 19],
	    #"inactive": [1, 0, 0, 0],
	    #"inname": ["Apple TV", "PlayStation", "Nintendo", "Input4"]
        return result

    async def get_cec_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get cec status")
        #"power": 1,
	    #"allinputname": ["Apple TV1", "PlayStation", "Nintendo", "Input4"],
	    #"alloutputname": ["L Projector", "L TV", "U TV", "Output4"],
	    #"currentInput": [0, 0, 0, 0],
	    #"currentOutput": [0, 0, 0, 0]
        return result

    async def get_system_status(self,) -> dict[str, Any]:
        result = await self.send_rest_req("get system status")
        #"power": 1,
	    #"baudrate": 6,
	    #"beep": 0,
	    #"lock": 0,
	    #"mode": 1,
	    #"version": "V1.08.08"
        return result

    async def set_video_source(self, output: int, input: int,) -> bool:
        self.validate_output(output)
        self.validate_input(input)
        return await self.send_rest_quick(
            "video switch",
            {
                "source": [
                    output, 
                    input,
                ],
            },
        )

    async def set_input_name(self, inputs_names: list[str],) -> bool:
        self.validate_input(inputs_names)
        return await self.send_rest_quick(
            "set input name",
            {
                "input": inputs_names,
            },
        )

    async def set_output_hdmi_name(self, outputs_names: list[str],) -> bool:
        self.validate_output(outputs_names)
        return await self.send_rest_quick(
            "set output name",
            {
                "output": outputs_names,
            },
        )

    async def set_output_cat_name(self, outputs_names: list[str],) -> bool:
        self.validate_output(outputs_names)
        return await self.send_rest_quick(
            "set output name",
            {
                "hdbtname": outputs_names,
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
    async def set_edid(self, input: int, edid: int,) -> bool:
        self.validate_input(input)
        return await self.send_rest_quick(
            "set edid",
            {
                "edid": [
                    input, 
                    edid,
                ],
            },
        )

    #TODO: async def set_user_edid(self,)
    #TODO: async def download_edid(self,)

    #scaler: 0 - Bypass, 1 - 4K to 1080p, 3 - Auto
    async def set_video_scaler(self, output: int, scaler: int,) -> bool:
        self.validate_output(output)
        return await self.send_rest_quick(
            "video scaler",
            {
                "scaler": [
                    output, 
                    scaler,
                ],
            },
        )

    async def set_input_tx_stream(self, input: int, stream: bool,) -> bool:
        self.validate_input(input)
        return await self.send_rest_quick(
            "video scaler",
            {
                "scaler": [
                    input,
                    int(stream),
                ],
            },
        )

    async def set_output_tx_stream(self, output: int, stream: bool,) -> bool:
        self.validate_output(output)
        port = self._inputs_count + output #hdmi 1-4, cat 5-8
        return await self.send_rest_quick(
            "video scaler",
            {
                "scaler": [
                    port, 
                    int(stream),
                ],
            },
        )

    async def set_panel_lock(self, lock: bool,) -> bool:
        return await self.send_rest_quick(
            "set panel lock",
            {
                "lock": int(lock),
            },
        )

    async def set_beep(self, beep: bool,) -> bool:
        return await self.send_rest_quick(
            "set beep",
            {
                "beep": int(beep),
            },
        )

    # 1 - 4800, 2 - 9600, 3 - 19200, 4 - 38400, 5 - 57600, 6 - 115200
    async def set_baudrate(self, baudrate: int,) -> bool:
        return await self.send_rest_quick(
            "set baudrate",
            {
                "baudrate": baudrate,
            },
        )

    #command: 1 - turnon, 2 - turnoff, 3 - keyup, 4 - keyleft, 5 - center, 6 - keyright, 7 - menu, 8 - keydown, 9 - back, 10 - prev, 11 - play, 12 - next, 13 - rewind, 14 - pause, 15 - forward, 16 - stop, 17 - mute, 18 - volumedown, 19 - volumeup
    async def send_cec_input(self, inputs: list[bool], command: int,) -> bool: 
        self.validate_input(inputs)
        return await self.send_rest_quick(
            "cec command",
            {
                "object": 0,
                "port": map(int, inputs),
                "index": command,
            },
        )

    #command: 0 - turnon, 1 - turnoff, 2 - mute, 3 - volumedown, 4 - volumeup, 5 - source
    async def send_cec_output(self, outputs: list[bool], command: int,) -> bool: #command:
        self.validate_output(outputs)
        return await self.send_rest_quick(
            "cec command",
            {
                "object": 1,
                "port": map(int, outputs),
                "index": command,
            },
        )

    async def preset_set(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset set",
            {
                "index": preset,
            },
        )
    
    async def preset_save(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset save",
            {
                "index": preset,
            },
        )

    async def preset_clear(self, preset: int,) -> bool:
        return await self.send_rest_quick(
            "preset clear",
            {
                "index": preset,
            },
        )

    async def set_power(self, power: bool,) -> bool:
        return await self.send_rest_quick(
            "set poweronoff",
            {
                "power": int(power),
            },
        )

    async def set_password(self, user: str, password: str, password_new: str) -> bool: #modify password
        return await self.send_rest_quick(
            "modify password",
            {
                "user": user,
                "password": password,
                "newpassword": password_new,
                "makesure": password_new,
            },
        )

    async def set_factory(self, factory: bool = True,) -> bool:
        return await self.send_rest_quick(
            "set factory",
            {
                "factory": int(factory),
            },
        )

    async def reboot(self, reboot: bool = True,) -> bool:
        return await self.send_rest_quick(
            "reboot",
            {
                "reboot": int(reboot),
            },
        )

    def validate_input(input: int | list) -> None:
        if not ((isinstance(input, list) and len(input) == self._inputs_count) or (input >= 1 and input <= self._inputs_count)):
            raise JtechOptionError

    def validate_output(output: int | list) -> None:
        if not ((isinstance(output, list) and len(output) == self._outputs_count) or (output >= 1 and output <= self._outputs_count)):
            raise JtechOptionError


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
    #Admin-Token ziming