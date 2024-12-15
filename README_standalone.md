# LabCA Standalone Version ![status-experimental](https://img.shields.io/badge/status-experimental-orange.svg)

As the ACME protocol is a standard (<a href="https://tools.ietf.org/html/rfc8555">RFC8555</a>) and not limited to boulder, there also are other implementations, e.g. <a href="https://smallstep.com/certificates/">step-ca</a> from Smallstep&trade; that you can run and manage yourself.

Getting started with step-ca is much easier than starting with boulder. But Smallstep is not providing a self-managed web GUI to easily see what certificates have been issued by step-ca and what their expiry statuses are. In fact they are using a very specific database storage that does not allow you to query the data directly from a normal database client either.

As the structure of the ACME data is pretty standard anyway, this standalone version of the LabCA GUI was created to work with step-ca (and potentially other ACME implementations in the future). It only works with their MySQL backend, as the BadgerDB backend has several limitations.

The standalone GUI is distributed as a single binary so that it can be easily installed and started. There is also a docker image available.


## Usage

### Install package

Download the latest .deb file for your platform architecture from the latest [release](https://github.com/hakwerk/labca/releases) on GitHub.

Install the .deb file:
```
dpkg -i labca-gui_<version>_<arch>.deb
```

The first time you can use the -init flag to create the config file. The location of the config file (default data/config.json), the IP address to listen on (default 0.0.0.0) and the port number (default 3000) can be specified, e.g.:
```
labca-gui -config stepca.json -address 127.0.0.1 -port 8080 -init
```

For consecutive starts you only need to specify the config file if it is not data/config.json
```
labca-gui -config stepca.json
```

The first time you connect to the application, you can create an admin account and specify the MySQL connection details for your step-ca database.

### Docker

When running a docker container you can map local filesystem files or directories as volumes to have the config data outside of the image, e.g.:
```
docker run -it --rm -v /home/username/acme/stepca_config.json:/usr/data/config.json ghcr.io/hakwerk/labca-standalone
```
or
```
docker run -it --rm -v /home/username/acme:/opt/acme ghcr.io/hakwerk/labca-standalone labca-gui -config /opt/acme/stepca.json
```


## systemd service

If you want to have the standalone version running all the time, even after a system reboot, you can create a service with the following steps (with thanks to [budulinek](https://github.com/budulinek)):
```
$ sudo mkdir -p /etc/labca
$ sudo labca-gui -config /etc/labca/labca.json -port 3000 -init
$ sudo useradd --system --home /etc/labca --shell /bin/false labca
$ sudo chown -R labca:labca /etc/labca
$ sudo nano /etc/systemd/system/labca.service
```
Put the following into that service file:
```
[Unit]
Description=LabCA service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=simple
User=labca
Group=labca
WorkingDirectory=/etc/labca
ExecStart=/usr/bin/labca-gui -config /etc/labca/labca.json
ExecReload=/bin/kill --signal HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=30
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
```
And finally
```
$ sudo systemctl daemon-reload
$ systemctl enable --now labca
```
