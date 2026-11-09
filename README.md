# ipinfo.py for Weechat

A WeeChat Python script for looking up IP address details without leaving your IRC client.

`weechat-ipinfo-py` is a Python script for the [WeeChat](https://weechat.org/) IRC client. It fetches information about a target IP address and prints the result directly in your active buffer. It's aimed at WeeChat users, network administrators, and IRC channel moderators who want quick network details inline.

## Features

- **Native integration:** runs in WeeChat's built-in Python scripting environment.
- **IP lookups:** retrieves network and metadata details for a given IP address.
- **Inline output:** shows results in the current WeeChat buffer.
## Installation

Requires WeeChat built with Python support.

```bash
git clone [https://github.com/](https://github.com/)<your-username>/weechat-ipinfo-py.git
mkdir -p ~/.local/share/weechat/python
cp weechat-ipinfo-py/ipinfo.py ~/.local/share/weechat/python/
```
