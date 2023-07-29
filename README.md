# pyjtechdigital

Python library for remote control of J-Tech Digital HDMI Matrix.

[![GitHub](https://img.shields.io/github/license/AlexOwl/pyjtechdigital)](https://github.com/AlexOwl/pyjtechdigital/blob/main/LICENSE)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/AlexOwl/pyjtechdigital)](https://github.com/AlexOwl/pyjtechdigital/releases)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/AlexOwl/pyjtechdigital/CI)](https://github.com/AlexOwl/pyjtechdigital/actions)

## Overview

pyjtechdigital is a Python library that provides an interface for remote controlling J-Tech Digital HDMI Matrix devices. It allows you to manage and control various aspects of the HDMI Matrix, such as power, input sources, output sources, video status, and network configuration.

## Installation

You can install the library using pip:

```bash
pip install pyjtechdigital
```

## Usage

```python
from jtechdigital import JtechClient

# Create a J-Tech Digital HDMI Matrix client instance
client = JtechClient(host='192.168.1.100')

# Connect to the HDMI Matrix
client.connect(user='admin', password='password')

# Get the status of the HDMI Matrix
status = client.get_status()
print(status)

# Switch video source
client.set_video_source(output=1, source=2)

# Set custom EDID for a source
client.set_custom_edid(custom_edid_index=1, edid="00FFFFFFFFFFFF00 ...")

# Control CEC devices
client.set_cec_sources(sources=[True, False, False, False])
client.send_cec_outputs(outputs=[True, False, True, False], command=3)

# ... (Other operations)

# Disconnect from the HDMI Matrix
client.disconnect()

```

## API Documentation

The API documentation for `pyjtechdigital` can be found [here](docs).

## License

`pyjtechdigital` is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.