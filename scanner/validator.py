import ipaddress
import socket
import re


def validate_target(target):
    target = target.strip()

    if any(char.isspace() for char in target):
        return False

    if not target:
        return False

    if len(target) > 253:
        return False

    hostname_pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$"

    # Direct IP address
    try:
        ip = ipaddress.ip_address(target)

        # Allow localhost
        if ip.is_loopback:
            return True

        # Allow private/local network addresses
        if ip.is_private:
            return True

        return False

    except ValueError:
        pass

    # Hostname
    if not re.fullmatch(hostname_pattern, target):
        return False

    try:
        resolved_ip = ipaddress.ip_address(
            socket.gethostbyname(target)
        )

        # Allow localhost/private addresses only
        if resolved_ip.is_loopback or resolved_ip.is_private:
            return True

        return False

    except (socket.gaierror, ValueError):
        return False