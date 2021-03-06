# reflex-agent

## Installation

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
