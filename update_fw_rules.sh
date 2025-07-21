#!/bin/bash

# This script whitelists the local dynamic IP address for the backoffice processing server
# using the current firewall rules for SSH/MySQL

# Get the current dynamic IP
MY_DYNAMIC_IP=$(/usr/bin/dig +short mydomain.dyndns.com)

# Only proceed if we got a valid IP address
if [[ -z "$MY_DYNAMIC_IP" ]]; then
  echo "Failed to retrieve dynamic IP."
  exit 1
fi

# Update firewall rules
/usr/local/psa/bin/modules/firewall/settings --set-rule \
  -id 1040 \
  -direction input \
  -action allow \
  -ports 3306/tcp \
  -from "$MY_DYNAMIC_IP" && \
/usr/local/psa/bin/modules/firewall/settings --set-rule \
  -id 1034 \
  -direction input \
  -action allow \
  -ports 22/tcp \
  -from "$MY_DYNAMIC_IP" && \
/usr/local/psa/bin/modules/firewall/settings --apply && \
/usr/local/psa/bin/modules/firewall/settings --confirm
