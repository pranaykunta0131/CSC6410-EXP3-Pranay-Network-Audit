#!/usr/bin/env python3

import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator


def run_ip(arguments):
    result = subprocess.run(
        ["ip", "-j"] + arguments,
        check=True,
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)


def read_dns_servers():
    servers = []
    resolv_conf = Path("/etc/resolv.conf")

    for line in resolv_conf.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])

    return servers


def detect_virtualization():
    result = subprocess.run(
        ["systemd-detect-virt"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip().lower()


def collect_host():
    links = run_ip(["link", "show"])
    addresses = run_ip(["addr", "show"])
    routes = run_ip(["route", "show", "default"])

    address_by_name = {item["ifname"]: item for item in addresses}
    is_wsl = detect_virtualization() == "wsl"

    interfaces = []

    for link in links:
        name = link["ifname"]
        address_info = address_by_name.get(name, {})
        ipv4 = []
        ipv6 = []

        for item in address_info.get("addr_info", []):
            value = f'{item["local"]}/{item["prefixlen"]}'

            if item.get("family") == "inet":
                ipv4.append(value)
            elif item.get("family") == "inet6":
                ipv6.append(value)

        flags = link.get("flags", [])
        operstate = link.get("operstate", "").upper()
        status = "up" if "UP" in flags or operstate == "UP" else "down"

        if name == "lo":
            interface_type = "loopback"
        elif is_wsl:
            interface_type = "virtual"
        elif link.get("link_type") == "ether":
            interface_type = "ethernet"
        else:
            interface_type = "other"

        interface = {
            "name": name,
            "type": interface_type,
            "oper-status": status,
            "mtu": link.get("mtu", 1500),
            "ipv4": ipv4,
            "ipv6": ipv6
        }

        mac = link.get("address")
        if mac:
            interface["mac"] = mac.lower()

        interfaces.append(interface)

    gateway = routes[0].get("gateway") if routes else None

    host = {
        "hostname": socket.gethostname(),
        "os": "linux",
        "collected-at": datetime.now(timezone.utc).isoformat(),
        "dns-server": read_dns_servers(),
        "interface": interfaces
    }

    if gateway:
        host["default-gateway"] = gateway

    return {"student-host:host": host}


def validate_observed(observed):
    schema = json.loads(Path("host_schema.json").read_text())
    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(observed),
        key=lambda error: list(error.absolute_path)
    )

    if not errors:
        print("SCHEMA: VALID")
        return

    print("SCHEMA: INVALID")
    for error in errors:
        path = "/" + "/".join(str(part) for part in error.absolute_path)
        print(f"Error at {path}: {error.message}")


def compare_with_intended(observed):
    intended = json.loads(Path("intended.json").read_text())
    expected_host = intended["student-host:host"]
    actual_host = observed["student-host:host"]

    print("\nDRIFT CHECK:")
    differences = 0

    for field, expected_value in expected_host.items():
        if field == "interface":
            actual_interfaces = {
                item["name"]: item
                for item in actual_host.get("interface", [])
            }

            for expected_interface in expected_value:
                name = expected_interface["name"]
                actual_interface = actual_interfaces.get(name)

                for key, expected_item in expected_interface.items():
                    actual_item = (
                        actual_interface.get(key)
                        if actual_interface is not None else None
                    )

                    if actual_item != expected_item:
                        print(
                            f"interface {name} / {key}: "
                            f"intended={expected_item!r}, "
                            f"observed={actual_item!r}"
                        )
                        differences += 1
        else:
            actual_value = actual_host.get(field)

            if actual_value != expected_value:
                print(
                    f"{field}: intended={expected_value!r}, "
                    f"observed={actual_value!r}"
                )
                differences += 1

    if differences == 0:
        print("No drift detected.")
    else:
        print(f"Drift detected: {differences} difference(s).")


def main():
    observed = collect_host()
    Path("observed.json").write_text(
        json.dumps(observed, indent=2) + "\n"
    )

    print("Collected live configuration and saved observed.json.")
    validate_observed(observed)
    compare_with_intended(observed)


if __name__ == "__main__":
    main()
