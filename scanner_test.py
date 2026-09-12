from scanner.validator import validate_target
from scanner.nmap_scanner import scan_target


target = input("Enter IP address or domain: ")

if validate_target(target):

    print("Target is valid!")
    print("Starting scan...")

    results = scan_target(target)

    print("\nScan Results:")
    print("------------------------------")

    for result in results:
        print(
            "Port:", result["port"],
            "| State:", result["state"],
            "| Service:", result["service"],
            "| Product:", result["product"],
            "| Version:", result["version"]
        )

else:

    print("Invalid target!")
    print("Scan cancelled.")