# reflex-agent


## Running with Docker

1. Create a file named `.env`
2. Add the following items

```
REFLEX_AGENT_PAIR_MODE=true
REFLEX_API_HOST=http://yourapihosthere
REFLEX_AGENT_PAIR_TOKEN=your.pairing.token
REFLEX_AGENT_ROLES=runner,poller
REFLEX_AGENT_IGNORE_TLS=true
```

1. Run the following command `docker run -v $PWD/.env:/.env reflex-agent:latest`

## Docker Compose

```
version: "3.8"
services:
    reflex-agent:
        image: zeroonesec/reflex-agent:latest
        volumes:
            - ./.env:/.env:ro
            - ./config.txt:/config.txt
```

## Manual Run

1. Log in to your management console
2. Click Agents
3. Click New Agent
4. Download the agent package
5. Pair the agent `python reflex-agent.py --pair --token <token> --console https://myconsole.com --roles poller,runner`
6. Run `python reflex-agent.py`


## Running as a Service

1. Create a service file

```
sudo vi /lib/systemd/system/reflex-agent.service
```

2. Add the service details to the file

```
[Unit]
Description=Reflex Agent
After=multi-user.target
Conflicts=getty@tty1.service

[Service]
Type=simple
WorkingDirectory=/etc/reflex
ExecStart=/usr/bin/python /etc/reflex/reflex-agent.py
StandardInput=tty-force

[Install]
WantedBy=multi-user.target
```

3. Enable the service 

```
sudo systemctl daemon-reload
sudo systemctl enable reflex-agent.service
sudo systemctl start reflex-agent.service
```
