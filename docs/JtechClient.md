# JtechClient Class Documentation

The `JtechClient` class represents a J-Tech Digital HDMI Matrix Client that allows you to control and interact with the HDMI matrix device.

## Constructor

### `JtechClient(host: str, session: ClientSession | None = None) -> None`

Initialize the device.

- `host` (str): The IP address or hostname of the HDMI matrix device.
- `session` (ClientSession | None): Optional. An existing `aiohttp.ClientSession` instance to reuse for requests, or None to create a new session.

## Methods

### `connect(user: str | None = None, password: str | None = None) -> None`

Open a connection to the HDMI matrix device.

- `user` (str | None): The username for authentication, or None for no authentication.
- `password` (str | None): The password for authentication, required if `user` is provided.

### `disconnect() -> None`

Close the connection to the HDMI matrix device.

### `get_status() -> JtechStatusResponse`

Get the status of the HDMI matrix device.

Returns:
- `JtechStatusResponse`: A response object containing the device status.

### `login(user: str, password: str) -> JtechLoginResponse`

Login to the HDMI matrix device with the provided username and password.

- `user` (str): The username for authentication.
- `password` (str): The password for authentication.

Returns:
- `JtechLoginResponse`: A response object containing the login status and token.

(... to be continued)
