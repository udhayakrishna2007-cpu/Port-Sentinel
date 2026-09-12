def analyze_results(results):

    recommendations = []

    for result in results:

        port = result.get("port")
        protocol = (result.get("protocol") or "").lower()
        service = (result.get("service") or "").lower()

        # TCP / GENERAL SERVICES

        if port == 21 or service == "ftp":

            recommendations.append({
                "severity": "High",
                "port": port,
                "service": "FTP",
                "message": "FTP may transmit credentials without encryption.",
                "recommendation": "Use SFTP or another encrypted file transfer method."
            })

        elif port == 23 or service == "telnet":

            recommendations.append({
                "severity": "High",
                "port": port,
                "service": "Telnet",
                "message": "Telnet communication is not encrypted.",
                "recommendation": "Disable Telnet and use SSH instead."
            })

        elif port == 3389:

            recommendations.append({
                "severity": "High",
                "port": port,
                "service": "RDP",
                "message": "Remote Desktop is exposed on this target.",
                "recommendation": "Restrict RDP access to trusted networks or use a VPN."
            })

        elif port == 445:

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "SMB",
                "message": "SMB is exposed on this target.",
                "recommendation": "Restrict SMB access to trusted networks and ensure unnecessary file sharing is disabled."
            })

        elif port == 80 or service == "http":

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "HTTP",
                "message": "HTTP traffic is not encrypted.",
                "recommendation": "Use HTTPS where sensitive information is transmitted."
            })

        elif port == 443 or service == "https":

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "HTTPS",
                "message": "HTTPS is available on this target.",
                "recommendation": "Keep HTTPS enabled and ensure certificates, TLS configuration, and supported protocols are maintained securely."
            })

        elif port == 5000:

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "Web Application",
                "message": "A web application is listening on port 5000.",
                "recommendation": "Verify that the development service is not unnecessarily exposed to untrusted networks."
            })

        elif port == 22 or service == "ssh":

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "SSH",
                "message": "SSH is available on this target.",
                "recommendation": "Keep SSH restricted to trusted networks and use strong authentication."
            })

        elif port in [3306, 5432, 1433, 27017]:

            database_names = {
                3306: "MySQL",
                5432: "PostgreSQL",
                1433: "Microsoft SQL Server",
                27017: "MongoDB"
            }

            database_name = database_names[port]

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": database_name,
                "message": f"{database_name} is exposed on this target.",
                "recommendation": "Restrict database access to trusted hosts and avoid exposing database services directly to untrusted networks."
            })

        # UDP SERVICES

        elif protocol == "udp" and (port == 123 or service == "ntp"):

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "NTP",
                "message": "NTP is available over UDP.",
                "recommendation": "Use trusted NTP servers and restrict unnecessary NTP exposure to trusted networks."
            })

        elif protocol == "udp" and (port == 137 or service == "netbios-ns"):

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "NetBIOS",
                "message": "NetBIOS Name Service is available over UDP.",
                "recommendation": "Disable NetBIOS where it is not required and restrict NetBIOS traffic to trusted networks."
            })

        elif protocol == "udp" and (port == 1900 or service == "upnp"):

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "UPnP",
                "message": "UPnP discovery is available over UDP.",
                "recommendation": "Disable UPnP where it is unnecessary and restrict device discovery to trusted local networks."
            })

        elif protocol == "udp" and (port == 3702 or service == "ws-discovery"):

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "WS-Discovery",
                "message": "WS-Discovery is available over UDP.",
                "recommendation": "Restrict device discovery to trusted local networks and disable unnecessary discovery services."
            })

        elif protocol == "udp" and (port == 4500 or service == "nat-t-ike"):

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "NAT-T/IKE",
                "message": "IPsec NAT Traversal traffic is available over UDP.",
                "recommendation": "Ensure IPsec/VPN services are intentionally enabled and restrict VPN access to authorized clients."
            })

        elif protocol == "udp" and (port == 5050 or service == "mmcc"):

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": "MMCC",
                "message": "A service identified as MMCC is available over UDP.",
                "recommendation": "Verify that this service is required and restrict access to trusted networks where appropriate."
            })

        elif protocol == "udp" and (
            port == 5353 or
            service == "zeroconf" or
            service == "mdns"
        ):

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "mDNS",
                "message": "Multicast DNS is available over UDP.",
                "recommendation": "Restrict mDNS to trusted local networks and disable multicast service discovery where it is unnecessary."
            })

        elif protocol == "udp" and (port == 5355 or service == "llmnr"):

            recommendations.append({
                "severity": "Medium",
                "port": port,
                "service": "LLMNR",
                "message": "LLMNR is available over UDP.",
                "recommendation": "Disable LLMNR where it is not required and prefer secure DNS-based name resolution."
            })

        # UNKNOWN UDP SERVICE

        elif protocol == "udp" and service:

            recommendations.append({
                "severity": "Info",
                "port": port,
                "service": service.upper(),
                "message": f"UDP service '{service}' was detected on this target.",
                "recommendation": "Verify that this service is required and restrict access to trusted networks where appropriate."
            })

    return recommendations