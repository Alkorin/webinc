# WebInC - Webex In Console
This is a Webex Teams console chat client. It uses Cisco's undocumented WebSocket API and thus doesn't rely on webhooks, so it doesn't need a public IP nor a tunnel.

This client currently only support chats.

## Configuration
The configuration is located in the file `~/.config/webinc/webinc.conf`. This file is in [toml format](https://godoc.org/github.com/BurntSushi/toml).

## Authentication
For now you have to provide to webinc a valid `authorization` token. To obtain one, you can go to https://developer.webex.com/login, Documentation, Api Reference, choose any API endpoint and you will be able to copy the `Authorization` token on the right.

The application will prompt you for this token at first launch and save it in its configuration file.

## License
GNU GPLv3
