import nmap


SCAN_TYPES = {
    "tcp": {
        "arguments": "-sT -sV --host-timeout 60s",
        "name": "TCP Scan"
    },

    "udp": {
        "arguments": "-sU -sV --host-timeout 300s",
        "name": "UDP Scan"
    },

    "syn": {
        "arguments": "-sS -sV --host-timeout 60s",
        "name": "SYN Scan"
    },

    "version": {
        "arguments": "-sV --host-timeout 60s",
        "name": "Service Version Detection"
    },

    "os": {
        "arguments": "-O -sV --host-timeout 120s",
        "name": "OS Detection"
    },

    "aggressive": {
        "arguments": "-A --host-timeout 180s",
        "name": "Aggressive Scan"
    }
}


def get_scan_type_name(scan_type):
    scan_type = (scan_type or "tcp").strip().lower()

    scan_config = SCAN_TYPES.get(scan_type)

    if not scan_config:
        return "Unknown Scan"

    return scan_config["name"]


def scan_target(target, scan_type="tcp"):

    try:

        scanner = nmap.PortScanner()

        scan_type = (scan_type or "tcp").strip().lower()

        scan_config = SCAN_TYPES.get(scan_type)

        if not scan_config:
            raise RuntimeError(
                f"Unsupported scan type: {scan_type}"
            )

        scanner.scan(
            target,
            arguments=scan_config["arguments"]
        )

        results = []

        for host in scanner.all_hosts():

            host_data = scanner[host]

            hostnames = []

            try:
                for hostname in host_data.get("hostnames", []):
                    name = hostname.get("name")

                    if name:
                        hostnames.append(name)
            except Exception:
                pass

            hostname = ", ".join(hostnames)

            host_state = host_data.get(
                "status",
                {}
            ).get(
                "state",
                "unknown"
            )

            addresses = host_data.get(
                "addresses",
                {}
            )

            mac_address = addresses.get(
                "mac",
                ""
            )

            vendor_data = host_data.get(
                "vendor",
                {}
            )

            vendor = ""

            if mac_address:
                vendor = vendor_data.get(
                    mac_address,
                    ""
                )

            os_name = ""
            os_family = ""
            os_generation = ""
            os_accuracy = ""

            os_matches = host_data.get(
                "osmatch",
                []
            )

            if os_matches:

                best_os = os_matches[0]

                os_name = best_os.get(
                    "name",
                    ""
                )

                os_accuracy = best_os.get(
                    "accuracy",
                    ""
                )

                os_classes = best_os.get(
                    "osclass",
                    []
                )

                if os_classes:

                    best_class = os_classes[0]

                    os_family = best_class.get(
                        "osfamily",
                        ""
                    )

                    os_generation = best_class.get(
                        "osgen",
                        ""
                    )

            host_info = {
                "host": host,
                "hostname": hostname,
                "host_state": host_state,
                "mac": mac_address,
                "vendor": vendor,
                "os_name": os_name,
                "os_family": os_family,
                "os_generation": os_generation,
                "os_accuracy": os_accuracy,
                "scan_type": scan_type
            }

            protocols = host_data.all_protocols()

            for protocol in protocols:

                ports = host_data[protocol].keys()

                for port in sorted(ports):

                    port_data = host_data[protocol][port]

                    result = {
                        "host": host,

                        "hostname": hostname,

                        "host_state": host_state,

                        "mac": mac_address,

                        "vendor": vendor,

                        "os_name": os_name,

                        "os_family": os_family,

                        "os_generation": os_generation,

                        "os_accuracy": os_accuracy,

                        "scan_type": scan_type,

                        "protocol": protocol,

                        "port": port,

                        "state": port_data.get(
                            "state",
                            "unknown"
                        ),

                        "service": port_data.get(
                            "name",
                            ""
                        ),

                        "product": port_data.get(
                            "product",
                            ""
                        ),

                        "version": port_data.get(
                            "version",
                            ""
                        ),

                        "extrainfo": port_data.get(
                            "extrainfo",
                            ""
                        ),

                        "reason": port_data.get(
                            "reason",
                            ""
                        )
                    }

                    results.append(result)

            # -------------------------------------------------
            # Host-level result
            #
            # OS/Aggressive scans may return useful host
            # information even when no port records exist.
            # -------------------------------------------------

            if not protocols:

                results.append({
                    "host": host,
                    "hostname": hostname,
                    "host_state": host_state,
                    "mac": mac_address,
                    "vendor": vendor,
                    "os_name": os_name,
                    "os_family": os_family,
                    "os_generation": os_generation,
                    "os_accuracy": os_accuracy,
                    "scan_type": scan_type,
                    "protocol": "",
                    "port": None,
                    "state": host_state,
                    "service": "",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "reason": ""
                })

        return results

    except nmap.PortScannerError as error:

        raise RuntimeError(
            f"Nmap scan failed: {error}"
        )

    except Exception as error:

        raise RuntimeError(
            f"Scanner error: {error}"
        )