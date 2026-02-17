#!/usr/bin/python3

import subprocess
import json
import sys
import logging

# This script runs on the Plesk server and whitelists the local dynamic IP address for the backoffice processing server
# eg. copy this into /usr/local/sbin

# This IP address will be included in all firewall rules that are being updated
fixed_whitelist_ip = "1.2.3.4"
dyndns_domain = "mydomain.dyndns.com"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/update_fw_rules.log'),
        logging.StreamHandler(sys.stdout)  # Keep console output as well
    ]
)
logger = logging.getLogger(__name__)

def get_dynamic_ip():
    """Get the current dynamic IP address."""
    try:
        result = subprocess.run(
            ['/usr/bin/dig', '+short', dyndns_domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        dynamic_ip = result.stdout.strip()
        
        if not dynamic_ip:
            logger.error("Failed to retrieve dynamic IP.")
            return None
            
        logger.info(f"Retrieved dynamic IP: {dynamic_ip}")
        return dynamic_ip
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to retrieve dynamic IP: {e}")
        return None

def get_firewall_rules():
    """Get current firewall rules in JSON format."""
    try:
        result = subprocess.run(
            ['/usr/local/psa/bin/modules/firewall/settings', '--list-json'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        
        rules = json.loads(result.stdout)
        logger.info(f"Retrieved {len(rules)} firewall rules")
        return rules
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to retrieve firewall rules: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse firewall rules JSON: {e}")
        return None

def find_rule_by_class(rules, class_name):
    """Find a firewall rule by its class name."""
    for rule in rules:
        if rule.get('class') == class_name:
            return rule
    return None

def update_firewall_rule(rule_id, direction, action, ports, from_ip):
    """Update a specific firewall rule."""
    try:
        cmd = [
            '/usr/local/psa/bin/modules/firewall/settings',
            '--set-rule',
            '-id', str(rule_id),
            '-direction', direction,
            '-action', action,
            '-ports', ports,
            '-from', from_ip
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        logger.info(f"Updated rule {rule_id} with IP {from_ip}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update rule {rule_id}: {e}")
        return False

def apply_firewall_changes():
    """Apply and confirm firewall changes."""
    try:
        # Apply changes
        subprocess.run(
            ['/usr/local/psa/bin/modules/firewall/settings', '--apply'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        
        # Confirm changes
        subprocess.run(
            ['/usr/local/psa/bin/modules/firewall/settings', '--confirm'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        
        logger.info("Firewall rules applied and confirmed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to apply firewall changes: {e}")
        return False

def main():
    """Main function to check and update firewall rules."""
    logger.info("Starting firewall rule update check")
    
    # Get the current dynamic IP
    dynamic_ip = get_dynamic_ip()
    if not dynamic_ip:
        sys.exit(1)
    
    # Get current firewall rules
    rules = get_firewall_rules()
    if not rules:
        sys.exit(1)
    
    # Find rules to whitelist (MySQL, SSH, Plesk admin TCP, Plesk admin HTTP/3)
    mysql_rule = find_rule_by_class(rules, 'mysql')
    ssh_rule = find_rule_by_class(rules, 'ssh')
    plesk_rule = find_rule_by_class(rules, 'plesk')
    plesk_http3_rule = find_rule_by_class(rules, 'plesk_http3')
    
    if not mysql_rule:
        logger.error("MySQL rule not found in firewall configuration")
        sys.exit(1)
    if not ssh_rule:
        logger.error("SSH rule not found in firewall configuration")
        sys.exit(1)
    if not plesk_rule:
        logger.error("Plesk admin (plesk) rule not found in firewall configuration")
        sys.exit(1)
    if not plesk_http3_rule:
        logger.error("Plesk admin HTTP/3 (plesk_http3) rule not found in firewall configuration")
        sys.exit(1)
    
    # Rules to check/update: (rule, label, ports for CLI)
    rules_to_update = [
        (mysql_rule, "MySQL", "3306/tcp"),
        (ssh_rule, "SSH", "22/tcp"),
        (plesk_rule, "Plesk admin", plesk_rule.get("ports", "8443/tcp,8880/tcp")),
        (plesk_http3_rule, "Plesk admin HTTP/3", plesk_http3_rule.get("ports", "8443/udp")),
    ]
    
    # Extract current information and log
    logger.info(f"Dynamic IP: {dynamic_ip}")
    whitelist_ip = (fixed_whitelist_ip.strip() + "," + dynamic_ip) if fixed_whitelist_ip.strip() else dynamic_ip
    for rule, label, _ in rules_to_update:
        logger.info(f"Current {label} rule ID: {rule.get('id')}, from: '{rule.get('from', '')}'")

    # Check if updates are needed
    needs_update = False
    for rule, label, _ in rules_to_update:
        current_from = rule.get("from", "")
        if current_from != whitelist_ip:
            logger.info(f"{label} rule IP changed from '{current_from}' to '{whitelist_ip}'")
            needs_update = True
    
    if not needs_update:
        logger.info("No IP changes detected. Firewall rules are up to date.")
        return
    
    # Update rules if needed
    success = True
    for rule, label, ports in rules_to_update:
        current_from = rule.get("from", "")
        if current_from != whitelist_ip:
            rule_id = rule.get("id")
            logger.info(f"Updating {label} rule (ID: {rule_id}) with IP: {whitelist_ip}")
            if not update_firewall_rule(rule_id, "input", "allow", ports, whitelist_ip):
                success = False
    
    # Apply changes if any updates were made
    if success and needs_update:
        logger.info("Applying firewall rule changes...")
        if not apply_firewall_changes():
            logger.error("Failed to apply firewall changes")
            sys.exit(1)
        else:
            logger.info("Firewall rules updated successfully")
    elif not success:
        logger.error("Failed to update firewall rules")
        sys.exit(1)

if __name__ == "__main__":
    main() 