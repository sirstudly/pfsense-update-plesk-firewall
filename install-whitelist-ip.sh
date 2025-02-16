#!/bin/sh

/usr/bin/fetch -o /usr/local/etc/rc.d/whitelist-ip.sh https://raw.githubusercontent.com/sirstudly/pfsense-update-plesk-firewall/refs/heads/master/rc.d/whitelist-ip.sh

# Fix permissions so it'll run
chmod +x /usr/local/etc/rc.d/whitelist-ip.sh

# Copy python script and config to /usr/local/whitelist-ip
echo "Copying files..."
mkdir -p /usr/local/whitelist-ip
/usr/bin/fetch -o /usr/local/whitelist-ip/main.py https://raw.githubusercontent.com/sirstudly/pfsense-update-plesk-firewall/refs/heads/master/main.py
/usr/bin/fetch -o /usr/local/whitelist-ip/.env https://raw.githubusercontent.com/sirstudly/pfsense-update-plesk-firewall/refs/heads/master/.env
echo "Configure /usr/local/whitelist-ip/.env manually."

# Add the startup variable to rc.conf.local.
# In the following comparison, we expect the 'or' operator to short-circuit, to make sure the file exists and avoid grep throwing an error.
if [ ! -f /etc/rc.conf.local ] || [ $(grep -c whitelist_ip_enable /etc/rc.conf.local) -eq 0 ]; then
  echo -n "Enabling the Whitelist IP service..."
  echo "whitelist_ip_enable=YES" >> /etc/rc.conf.local
  echo " done."
fi
