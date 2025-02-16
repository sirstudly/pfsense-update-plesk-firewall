from types import SimpleNamespace

import requests
import json
import configparser
import subprocess
import time
import ipaddress
import logging
from logging.handlers import TimedRotatingFileHandler

from bs4 import BeautifulSoup

session = requests.Session()
EXTERNAL_IP_COMMAND = ''
PLESK_USERNAME = None
PLESK_PASSWORD = None
PLESK_HOST = None
LOG_FILE = "firewall.log"
LOGGER = logging.getLogger("pfSense-update-plesk-firewall")
LOOP_INTERVAL_SEC = 60 * 30

def load_config() -> None:
    global EXTERNAL_IP_COMMAND, PLESK_USERNAME, PLESK_PASSWORD, PLESK_HOST, LOG_FILE, LOOP_INTERVAL_SEC
    config = configparser.ConfigParser()
    config.read('.env')
    EXTERNAL_IP_COMMAND = config['Settings'].get("EXTERNAL_IP_COMMAND")
    PLESK_USERNAME = config['Settings'].get("PLESK_USERNAME")
    PLESK_PASSWORD = config['Settings'].get("PLESK_PASSWORD")
    PLESK_HOST = config['Settings'].get("PLESK_HOST")
    LOG_FILE = config['Settings'].get("LOG_FILE", LOG_FILE)
    LOOP_INTERVAL_SEC = int(config['Settings'].get("LOOP_INTERVAL_SEC", str(LOOP_INTERVAL_SEC)))


def load_logging_config() -> None:
    LOGGER.setLevel(logging.INFO)
    handler = TimedRotatingFileHandler(LOG_FILE, when="midnight", interval=1, backupCount=7)
    handler.suffix = "%Y-%m-%d"
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)


def get_external_ip() -> str:
    try:
        result = subprocess.run(EXTERNAL_IP_COMMAND, shell=True, capture_output=True, text=True, check=True)
        external_ip = result.stdout.strip()
        LOGGER.info(f"External IP: {external_ip}")
        ipaddress.IPv4Address(external_ip)  # throws AddressValueError if not valid
        return external_ip
    except subprocess.CalledProcessError as e:
        LOGGER.error(f"Failed to get external IP with error: {e.returncode}\n{e.stderr}")
        raise e


def login() -> None:
    payload = {
        'login_name': PLESK_USERNAME,
        'passwd': PLESK_PASSWORD,
        'locale_id': 'default'
    }
    login_url = f'https://{PLESK_HOST}/login_up.php'
    response = session.post(login_url, data=payload)
    if not hasattr(response, "status_code") or response.status_code != 200:
        if hasattr(response, "content"):
            LOGGER.error(response.content)
        raise Exception('Login failed')


def get_forgery_protection_token() -> str:
    response = session.get(f"https://{PLESK_HOST}/modules/firewall/")
    if not hasattr(response, "status_code") or response.status_code != 200:
        if hasattr(response, "content"):
            LOGGER.error(response.content)
        raise Exception('Failed to retrieve forgery protection token')
    soup = BeautifulSoup(response.content, 'html.parser')
    token_meta = soup.find('meta', id='forgery_protection_token')
    if token_meta:
        return token_meta.get('content')
    LOGGER.error(response.content)
    raise Exception('Failed to retrieve forgery protection token')


def get_firewall_rules() -> object:
    response = session.get(f'https://{PLESK_HOST}/modules/firewall/index.php/api/list')

    if hasattr(response, "status_code") and response.status_code == 200:
        response = json.loads(response.content, object_hook=lambda d: SimpleNamespace(**d))
        if hasattr(response, "status") and response.status == "success" and hasattr(response, "data") and hasattr(response.data, "rules"):
            return response.data
    raise Exception('Failed to retrieve firewall rules. ' + response.content)


def whitelist_ipaddress(forgery_protection_token: str, firewall_rules: object, service_class: str, ipaddr: str) -> None:
    matched_rules = list(filter(lambda r: getattr(r, 'type') == "service" and getattr(r, 'class') == service_class, firewall_rules.rules))
    for rule in matched_rules:
        if hasattr(rule, 'from') and len(list(filter(lambda ip: ip == ipaddr, getattr(rule, 'from')))) == 0:
            LOGGER.info(f"{ipaddr} not whitelisted in {service_class} rule... Updating rule.")
            update_rule(forgery_protection_token, rule.id, ipaddr)
            return
    if len(matched_rules) == 0:
        raise Exception(f"Unable to find matching {service_class} rule.")


def update_rule(forgery_protection_token: str, rule_id: int, ipaddr: str) -> None:
    payload = {
        "id": rule_id,
        "data": {
            "direction": "input",
            "action": "allow",
            "from": [
                ipaddr
            ]
        }
    }
    LOGGER.info(f"Updating rule {rule_id} with IP address {ipaddr}...")
    response = session.post(f'https://{PLESK_HOST}/modules/firewall/index.php/api/save-rule', json=payload,
                            headers={'Content-Type': 'application/json',
                                     'X-Forgery-Protection-Token': forgery_protection_token})

    if hasattr(response, "status_code") and response.status_code == 200:
        response = json.loads(response.content, object_hook=lambda d: SimpleNamespace(**d))
        if hasattr(response, "status") and response.status != "success":
            LOGGER.error(f'Failed to update firewall rule: {response.status}')
            LOGGER.error(response.content)
    else:
        LOGGER.error(f'Failed to update firewall rule: [{response.status_code if hasattr(response, "status_code") else "?"}]: {response.content}')
        LOGGER.error(response.content)


def apply_changes(forgery_protection_token: str) -> None:
    LOGGER.info("Applying firewall changes...")
    response = session.post(f'https://{PLESK_HOST}/modules/firewall/index.php/api/apply-changes',
                            headers={'Content-Type': 'application/json',
                                     'X-Forgery-Protection-Token': forgery_protection_token})

    if hasattr(response, "status_code") and response.status_code == 200:
        response = json.loads(response.content, object_hook=lambda d: SimpleNamespace(**d))
        if hasattr(response, "status") and response.status != "success":
            LOGGER.error(f'Failed to apply firewall changes: {response.status}')
            LOGGER.error(response.content)
    else:
        LOGGER.error(f'Failed to apply firewall changes: [{response.status_code if hasattr(response, "status_code") else "?"}]: {response.content}')
        LOGGER.error(response.content)


def main():
    load_logging_config()
    while True:
        try:
            load_config()  # can be modified at runtime
            external_ip = get_external_ip()
            login()
            rules = get_firewall_rules()
            forgery_protection_token = get_forgery_protection_token()
            whitelist_ipaddress(forgery_protection_token, rules, "ssh", external_ip)
            whitelist_ipaddress(forgery_protection_token, rules, "mysql", external_ip)
            rules = get_firewall_rules()
            if hasattr(rules, 'isModified') and rules.isModified:
                apply_changes(forgery_protection_token)
                LOGGER.info("Updated firewall rules: " + repr(rules))
            else:
                LOGGER.info("No new firewall rules applied.")

        except Exception as e:
            LOGGER.error('Error: exception: ' + str(e))
        time.sleep(LOOP_INTERVAL_SEC)


if __name__ == "__main__":
    main()
