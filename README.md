pfsense-update-plesk-firewall
===================

A Python script to update the whitelisted IP address within firewall rules in a Plesk instance.

## Features

- Installs as a service.
- Configured with a customisable .env file.
- Logs activity to a rotating log file for easy troubleshooting.

Usage
-----

To install the script, run this one-line command, which downloads the install script from Github and executes it with sh:

```
  fetch -o - https://raw.githubusercontent.com/sirstudly/pfsense-update-plesk-firewall/refs/heads/master/install-whitelist-ip.sh | sh -s
```

If you don't already have the Python package installer (pip) installed, install it now:
```
  /usr/local/bin/python3.11 -m ensurepip
  /usr/local/bin/pip3.11 --version  # check installed version
```

Install the package requirements:
```
  cd /usr/local/whitelist-ip/
  /usr/local/bin/pip3.11 install -r requirements.txt
```

Configuration
---------------------

Update `/usr/local/whitelist-ip/.env` with the appropriate values.

Starting and Stopping
---------------------

To start and stop the controller, use the `service` command from the command line.

- To start the service:

  ```
    service whitelist_ip.sh start
  ```
  The 'start' command exits immediately while the startup continues in the background.

- To stop the service:

  ```
    service whitelist_ip.sh stop
  ```
