import configparser
import ipaddress
import logging
import subprocess
import time
from dataclasses import dataclass
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Dict

import requests
from bs4 import BeautifulSoup

# Use a global session for HTTP requests.
session = requests.Session()


@dataclass
class Config:
    external_ip_command: str
    plesk_username: str
    plesk_password: str
    plesk_host: str
    log_file: str
    loop_interval_sec: int


def load_config(path: str = ".env") -> Config:
    """
    Loads configuration from the given .env file.
    """
    config_parser = configparser.ConfigParser()
    config_parser.read(path)
    settings = config_parser['Settings']
    return Config(
        external_ip_command=settings.get("EXTERNAL_IP_COMMAND"),
        plesk_username=settings.get("PLESK_USERNAME"),
        plesk_password=settings.get("PLESK_PASSWORD"),
        plesk_host=settings.get("PLESK_HOST"),
        log_file=settings.get("LOG_FILE", "firewall.log"),
        loop_interval_sec=int(settings.get("LOOP_INTERVAL_SEC", str(60 * 30)))
    )


def setup_logging(log_file: str) -> logging.Logger:
    """
    Configures and returns a logger.
    """
    logger = logging.getLogger("pfSense-update-plesk-firewall")
    logger.setLevel(logging.INFO)
    # Avoid adding multiple handlers if setup_logging is called multiple times.
    if not logger.handlers:
        handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7)
        handler.suffix = "%Y-%m-%d"
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def get_external_ip(cmd: str, logger: logging.Logger) -> str:
    """
    Runs a shell command to obtain the external IP address, validates it, and returns it.
    """
    external_ip = ''
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        external_ip = result.stdout.strip()
        logger.info(f"External IP: {external_ip}")
        # Validate the IP address.
        ipaddress.IPv4Address(external_ip)
        return external_ip
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get external IP. Return code: {e.returncode}, stderr: {e.stderr}")
        raise
    except ipaddress.AddressValueError:
        logger.error(f"Invalid IP address obtained: {external_ip}")
        raise


def login(config: Config, logger: logging.Logger) -> None:
    """
    Logs into the Plesk host using the provided credentials.
    """
    payload = {
        'login_name': config.plesk_username,
        'passwd': config.plesk_password,
        'locale_id': 'default'
    }
    login_url = f'https://{config.plesk_host}/login_up.php'
    response = session.post(login_url, data=payload)
    if response.status_code != 200:
        logger.error(f"Login failed. Response: {response.text}")
        raise Exception('Login failed')


def get_forgery_protection_token(config: Config, logger: logging.Logger) -> str:
    """
    Retrieves the forgery protection token from the Plesk firewall module page.
    """
    url = f"https://{config.plesk_host}/modules/firewall/"
    response = session.get(url)
    if response.status_code != 200:
        logger.error(f"Failed to retrieve forgery protection token. Response: {response.text}")
        raise Exception('Failed to retrieve forgery protection token')
    soup = BeautifulSoup(response.content, 'html.parser')
    token_meta = soup.find('meta', id='forgery_protection_token')
    if token_meta:
        return token_meta.get('content')
    logger.error("Forgery protection token meta tag not found.")
    raise Exception('Failed to retrieve forgery protection token')


def get_firewall_rules(config: Config, logger: logging.Logger) -> Dict[str, Any]:
    """
    Retrieves the current firewall rules from the Plesk API.
    """
    url = f'https://{config.plesk_host}/modules/firewall/index.php/api/list'
    response = session.get(url)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") == "success" and "data" in data and "rules" in data["data"]:
            return data["data"]
    logger.error(f"Failed to retrieve firewall rules. Response: {response.text}")
    raise Exception('Failed to retrieve firewall rules.')


def whitelist_ipaddress(token: str, firewall_rules: Dict[str, Any], service_class: str,
                        ipaddr: str, config: Config, logger: logging.Logger) -> None:
    """
    Ensures that the specified IP address is whitelisted for a given service class.
    """
    rules = firewall_rules.get("rules", [])
    matched_rules = [r for r in rules if r.get("type") == "service" and r.get("class") == service_class]
    for rule in matched_rules:
        # 'from' is a reserved keyword; use dictionary lookup.
        rule_from = rule.get("from", [])
        if ipaddr not in rule_from:
            logger.info(f"{ipaddr} not whitelisted in {service_class} rule... Updating rule.")
            update_rule(token, rule["id"], ipaddr, config, logger)
            return
    if not matched_rules:
        raise Exception(f"Unable to find matching {service_class} rule.")


def update_rule(token: str, rule_id: int, ipaddr: str, config: Config, logger: logging.Logger) -> None:
    """
    Updates a firewall rule to add the given IP address.
    """
    payload = {
        "id": rule_id,
        "data": {
            "direction": "input",
            "action": "allow",
            "from": [ipaddr]
        }
    }
    logger.info(f"Updating rule {rule_id} with IP address {ipaddr}...")
    url = f'https://{config.plesk_host}/modules/firewall/index.php/api/save-rule'
    headers = {
        'Content-Type': 'application/json',
        'X-Forgery-Protection-Token': token
    }
    response = session.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") != "success":
            logger.error(f"Failed to update firewall rule: {data.get('status')}")
            logger.error(response.text)
    else:
        logger.error(f"Failed to update firewall rule: [{response.status_code}]: {response.text}")


def apply_changes(token: str, config: Config, logger: logging.Logger) -> None:
    """
    Applies any pending firewall rule changes.
    """
    logger.info("Applying firewall changes...")
    url = f'https://{config.plesk_host}/modules/firewall/index.php/api/apply-changes'
    headers = {
        'Content-Type': 'application/json',
        'X-Forgery-Protection-Token': token
    }
    response = session.post(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") != "success":
            logger.error(f"Failed to apply firewall changes: {data.get('status')}")
            logger.error(response.text)
        else:
            logger.info("Firewall changes applied successfully.")
            # confirm_activation(token, data.get("data"), config, logger)
    else:
        logger.error(f"Failed to apply firewall changes: [{response.status_code}]: {response.text}")


def confirm_activation(token: str, applied_action, config: Config, logger: logging.Logger) -> None:
    """
    Confirm firewall rule changes have been applied.
    """
    logger.info("Confirming firewall rules activation...")
    url = f'https://{config.plesk_host}/modules/firewall/index.php/api/confirm-activation'
    headers = {
        'Content-Type': 'application/json',
        'X-Forgery-Protection-Token': token
    }
    response = session.post(url, json=applied_action, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data.get("status") != "success":
            logger.error(f"Failed to confirm firewall rules activation: {data.get('status')}")
            logger.error(response.text)
    else:
        logger.error(f"Failed to confirm firewall rules activation: [{response.status_code}]: {response.text}")


def main() -> None:
    try:
        config = load_config()
    except Exception as e:
        print(f"Error loading config: {e}")
        return

    logger = setup_logging(config.log_file)

    try:
        while True:
            try:
                external_ip = get_external_ip(config.external_ip_command, logger)
                login(config, logger)
                firewall_rules = get_firewall_rules(config, logger)
                token = get_forgery_protection_token(config, logger)
                whitelist_ipaddress(token, firewall_rules, "ssh", external_ip, config, logger)
                whitelist_ipaddress(token, firewall_rules, "mysql", external_ip, config, logger)
                # Refresh rules and apply changes if needed
                firewall_rules = get_firewall_rules(config, logger)
                if firewall_rules.get("isModified", False):
                    apply_changes(token, config, logger)
                    logger.info(f"Updated firewall rules: {firewall_rules}")
                else:
                    logger.info("No new firewall rules applied.")
            except Exception as e:
                logger.exception("Error occurred during processing:" + str(e))
            time.sleep(config.loop_interval_sec)
            # Allow runtime changes to config
            config = load_config()
    except KeyboardInterrupt:
        logger.info("Exiting on keyboard interrupt.")


if __name__ == "__main__":
    main()
