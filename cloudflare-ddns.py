#!/usr/bin/env python3
#   cloudflare-ddns.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain
#                Access your home network remotely via a custom domain
#                A small, 🕵️ privacy centric, and ⚡
#                lightning fast multi-architecture Docker image for self hosting projects.
import json
import os
import signal
import sys
import threading
import time
import requests
from string import Template
from urllib.parse import urlparse

__version__ = "1.0.3"

CONFIG_PATH = os.environ.get("CONFIG_PATH", os.getcwd())
ENV_VARS = {key: value for (key, value) in os.environ.items() if key.startswith("CF_DDNS_")}

class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print("\n🛑 Stopping main thread after the cycle (1 Cycle is chosen ttl from config.json) or after the sleep cycle...\n")
        self.kill_now.set()


class CloudflareDDNS:
    def __init__(self, killer: GracefulExit = None):
        self.print_header(f"📡 Starting cloudflare-ddns v{__version__}")
        self.config = None
        self.ttl = 300
        self.killer = killer
        self.warnings = {"ipv4": False,
                        "ipv6": False,
                        "ipv4_secondary": False,
                        "ipv6_secondary": False}
        self.purge_unknown_records, self.ipv4_enabled , self.ipv6_enabled, self.cyclic_config_read = False, False, False, False
        self.ipv4_endpoints = ("https://1.1.1.1/cdn-cgi/trace", "https://ipv4.icanhazip.com")
        self.ipv6_endpoints = ("https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://ipv6.icanhazip.com")
        self.load_config()

    def load_config(self):
        """Load the configuration file with records to update."""
        try:
            with open(os.path.join(CONFIG_PATH, "config.json")) as config_file:
                self.config = (json.loads(Template(config_file.read()).safe_substitute(ENV_VARS)) if ENV_VARS
                          else json.loads(config_file.read()))
        except Exception as e:
            print(f"😡 Error reading config.json {e}")
            time.sleep(self.config.get("sleep_time") if self.config else 10)
            self.load_config() if self.cyclic_config_read else self.killer.kill_now.set()

    def parse_config(self):
        """Parse the configuration file."""
        if not self.config:
            return

        self.ttl = max(1, int(self.config.get("ttl", 300)))
        print(f"\n⚙️  TTL is too low - defaulting to 1 (auto)" if self.ttl < 30 else f"\n🕰️  Updating records with {self.ttl} ttl.\n⚙️  To change the duration of the update, change the ttl in the configuration file: config.json\n")
        self.ipv4_enabled = self.config.get("a", True)
        print(f"🕰️  Updating IPv4 (A) records with {self.ttl} ttl." if self.ipv4_enabled else "⚙️  Updating IPv4 (A) is disabled")
        self.ipv6_enabled = self.config.get("aaaa", True)
        print(f"🕰️  Updating IPv6 (AAAA) records with {self.ttl} ttl.\n" if self.ipv6_enabled else "⚙️  Updating IPv6 (AAAA) is disabled\n")
        self.purge_unknown_records = self.config.get("purgeUnknownRecords", False)
        print(f"🗑️ Purging unknown records is enabled." if self.purge_unknown_records else "⚙️  Purging unknown records is disabled")
        self.cyclic_config_read = self.config.get("cyclic_config_read", False)
        print(f"🔁 Cyclic config read is enabled" if self.cyclic_config_read else "⚙️  Cyclic config read is disabled")

    def delete_entries(self, record_type):
        """Delete stale records from Cloudflare.
        Args:
          record_type (str): The type of DNS record to delete.
        """
        for option in self.config["cloudflare"]:
            records = self.cf_api(f"zones/{option['zone_id']}/dns_records?per_page=100&type={record_type}", "GET", option)
            if not records or not records.get("result"):
                time.sleep(self.config.get("sleep_time", 10))
                return
            for record in records["result"]:
                self.cf_api(f"zones/{option['zone_id']}/dns_records/{record['id']}","DELETE", option)
                print(f"🗑️ Deleted stale record {record['id']}")

    def get_ip(self, endpoint):
        """Get the public IP address from an endpoint.
        Args:
            endpoint (str): The endpoint to get the IP address from.
        Returns:
            str: The public IP address.
        """
        print(f"\n🕰️  Getting IP from {endpoint}")
        response = requests.get(endpoint, timeout=10)
        response.raise_for_status()
        lines = [line for line in response.text.split("\n") if line.strip()]
        return dict(i.split("=") for i in lines)["ip"] if len(lines) > 1 else lines[0]

    def get_ips(self):
        """Get the public IP addresses from the configured endpoints."""
        ipv4, ipv6 = None, None
        if self.ipv4_enabled:
            ipv4 = self.try_get_ip(self.ipv4_endpoints, "ipv4")
            if ipv4 is None and self.purge_unknown_records:
                self.delete_entries("A")
        if self.ipv6_enabled:
            ipv6 = self.try_get_ip(self.ipv6_endpoints, "ipv6")
            if ipv6 is None and self.purge_unknown_records:
                self.delete_entries("AAAA")
        return {"ipv4": {"type": "A", "ip": ipv4} if ipv4 else None,
                "ipv6": {"type": "AAAA", "ip": ipv6} if ipv6 else None}

    def try_get_ip(self, endpoints, ip_version):
        """Try to get the public IP address from the configured endpoints."""
        for i, endpoint in enumerate(endpoints):
            try:
                return self.get_ip(endpoint)
            except Exception as e:
                key = ip_version if i == 0 else f"{ip_version}_secondary"
                if not self.warnings.get(key, False):
                    self.warnings[key] = True
                    if i != len(endpoints) - 1:
                        print(f"🧩 {ip_version.upper()} not detected via {urlparse(endpoint).netloc}, trying {urlparse(endpoints[i+1]).netloc}")
                    else:
                        print(f"🧩 {ip_version.upper()} not detected via {urlparse(endpoint).netloc}.\nVerify that your Standardgateway is set correctly and your ISP or/and DNS provider isn't blocking Cloudflare's IPs. Error: {e}")
        return None

    def update_ips(self):
        """Update the Cloudflare DNS records with the public IP addresses."""
        self.load_config() if self.cyclic_config_read else None
        self.parse_config()
        for ip in filter(None, self.get_ips().values()):
            self.commit_record(ip)
            if not self.config.get("load_balancer", False):
                self.update_load_balancer(ip)

    def commit_record(self, ip):
        for option in self.config.get("cloudflare", []):
            subdomains = option.get("subdomains", [])
            base_domain_name = self.cf_api(f"zones/{option['zone_id']}", "GET", option)["result"]["name"]

            for subdomain in subdomains:
                fqdn = (f"{subdomain['name'].lower().strip()}.{base_domain_name}" if subdomain not in ("", "@") else base_domain_name)
                record = {"type": ip["type"],
                          "name": fqdn,
                          "content": ip["ip"],
                          "proxied": option.get("proxied", False),
                          "ttl": self.ttl}
                print(f"📡 Updating/Adding record {record}")
                self.cf_api(f"zones/{option['zone_id']}/dns_records", "POST", option, {}, record)

    def update_load_balancer(self, ip):
        """Update Cloudflare Load Balancer IP addresses ?
        I am not sure if it works or not. It was in the original script but was commented out so i kept it here.
        with the condition of the load balancer being enabled in the config. 
        Args:
            ip (dict): The IP address to update.
        """
        for option in self.config.get("load_balancer", []):
            pools = self.cf_api("user/load_balancers/pools", "GET", option)
            if not pools or "result" not in pools:
                continue

            # find next suitable pool
            pool = next((p for p in pools["result"] if p.get("id") == option.get("pool_id")), None)
            if pool is None:
                continue

            origins = pool.get("origins", [])
            
            # find next suitable origin
            origin = next((o for o in origins if o.get("name") == option.get("origin")), None)
            if origin is None:
                continue

            origin["address"] = ip.get("ip")
            data = {"origins": origins}
            response = self.cf_api(f'user/load_balancers/pools/{option["pool_id"]}', "PATCH", option, {}, data)

    def cf_api(self, endpoint, method, config, headers={}, data=None):
        """Make a Cloudflare API request.
        Args:
          endpoint (str): The endpoint to make the request to.
          method (str): The method to use for the request.
          config (dict): The configuration to use for the request.
          headers (dict, optional): The headers to use for the request.
          data (dict, optional): The data to use for the request.
        Returns:
          dict: The response from the request.
        """
        headers = ({"Authorization": f"Bearer {config['authentication']['api_token']}"} if config["authentication"]["api_token"]
              else {"X-Auth-Email": config["authentication"]["api_key"]["account_email"],
                    "X-Auth-Key": config["authentication"]["api_key"]["api_key"]})
        try:
            response = requests.request(method, f"https://api.cloudflare.com/client/v4/{endpoint}",headers=headers, json=data)
            return response.json() if response.ok else None
        except Exception as e:
            print(f"😡 Error in {method} request to {endpoint}: {e}")
            return None
          
    def print_header(self, title):
      """Print a formatted header with the given title.
      Args:
        title (str): The title to print.
      """
      len_title = len(title) + 5
      print(f"\n{'#' * len_title}\n# {title} #\n{'#' * len_title}\n")

if __name__ == "__main__":
    if sys.version_info < (3, 5):
        raise Exception("🐍 This script requires Python 3.5+")

    killer = GracefulExit()
    ddns = CloudflareDDNS(killer)
    
    if len(sys.argv) > 1 and sys.argv[1] == "--repeat":
        while not killer.kill_now.is_set():
            ddns.update_ips()
            time.sleep(ddns.ttl) if not killer.kill_now.is_set() else exit(0)
    elif not killer.kill_now.is_set():
        print(f"❓ Unrecognized parameter '{sys.argv[1]}'." if len(sys.argv) > 1 else f"\n\n💡 Usage to run it in loop: python -u {sys.argv[0].split('/')[-1]} --repeat")
        print(f"\n🕰️  Tyring to update records 1 time...")
        ddns.update_ips()
        time.sleep(ddns.config.get("sleep_time") if ddns.config else 10)
