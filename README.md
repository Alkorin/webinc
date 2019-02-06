# WebInc - Webex In Console
This is a Webex Teams console chat client. It uses Cisco's undocumented WebSocket API and thus doesn't rely on webhooks, so it doesn't need a public IP nor a tunnel.

This client currently only support chats.

## Authentication
For now you have to provide to webinc a valid `authorization` token. To obtain one, you can go to https://developer.webex.com/login, Documentation, Api Reference, choose any API endpoint and you will be able to copy the `Authorization` token on the right.

Then, create a `webinc.conf` file next to webinc and add the authorization token. This file is in [YAML format](https://fr.wikipedia.org/wiki/YAML).

Example:
```
$ cat webinc.conf
- key: auth-token
  value: NDRlOTZhOGQtMWY0ZS00MjMyLWIzNzItMjVlOGU5NjBmZGNkMWMwY2JmMzItMDVl_PF84_consumer
```

## License
GNU GPLv3
