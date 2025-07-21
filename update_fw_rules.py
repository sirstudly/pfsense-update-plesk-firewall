#!/usr/bin/python3

import subprocess
import json
import sys
import logging

# This script runs on the Plesk server and whitelists the local dynamic IP address for the backoffice processing server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_dynamic_ip():
    """Get the current dynamic IP address."""
    try:
        result = subprocess.run(
            ['/usr/bin/dig', '+short', 'mydomain.dyndns.com'],
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
    
    # Find MySQL and SSH rules
    mysql_rule = find_rule_by_class(rules, 'mysql')
    ssh_rule = find_rule_by_class(rules, 'ssh')
    
    if not mysql_rule:
        logger.error("MySQL rule not found in firewall configuration")
        sys.exit(1)
        
    if not ssh_rule:
        logger.error("SSH rule not found in firewall configuration")
        sys.exit(1)
    
    # Extract current information
    mysql_rule_id = mysql_rule.get('id')
    ssh_rule_id = ssh_rule.get('id')
    mysql_current_ip = mysql_rule.get('from', '')
    ssh_current_ip = ssh_rule.get('from', '')
    
    logger.info(f"Current MySQL rule ID: {mysql_rule_id}, IP: '{mysql_current_ip}'")
    logger.info(f"Current SSH rule ID: {ssh_rule_id}, IP: '{ssh_current_ip}'")
    logger.info(f"Dynamic IP: {dynamic_ip}")
    
    # Check if updates are needed
    needs_update = False
    
    if mysql_current_ip != dynamic_ip:
        logger.info(f"MySQL rule IP changed from '{mysql_current_ip}' to '{dynamic_ip}'")
        needs_update = True
    
    if ssh_current_ip != dynamic_ip:
        logger.info(f"SSH rule IP changed from '{ssh_current_ip}' to '{dynamic_ip}'")
        needs_update = True
    
    if not needs_update:
        logger.info("No IP changes detected. Firewall rules are up to date.")
        return
    
    # Update rules if needed
    success = True
    
    if mysql_current_ip != dynamic_ip:
        logger.info(f"Updating MySQL rule (ID: {mysql_rule_id}) with IP: {dynamic_ip}")
        if not update_firewall_rule(mysql_rule_id, 'input', 'allow', '3306/tcp', dynamic_ip):
            success = False
    
    if ssh_current_ip != dynamic_ip:
        logger.info(f"Updating SSH rule (ID: {ssh_rule_id}) with IP: {dynamic_ip}")
        if not update_firewall_rule(ssh_rule_id, 'input', 'allow', '22/tcp', dynamic_ip):
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