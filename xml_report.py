import xml.etree.ElementTree as ET


def generate_xml_report(
    output_path,
    scan,
    results,
    recommendations,
    high_count,
    medium_count,
    info_count,
    hosts_found,
    open_ports,
    services_found,
    security_status
):

    # Root element
    root = ET.Element("port_sentinel_report")

    # -------------------------------------------------
    # SCAN INFORMATION
    # -------------------------------------------------

    scan_info = ET.SubElement(root, "scan_information")

    ET.SubElement(
        scan_info,
        "scan_id"
    ).text = str(scan[0])

    ET.SubElement(
        scan_info,
        "target"
    ).text = str(scan[1])

    ET.SubElement(
        scan_info,
        "scan_date"
    ).text = str(scan[2])

    ET.SubElement(
        scan_info,
        "security_status"
    ).text = str(security_status)

    # -------------------------------------------------
    # SCAN SUMMARY
    # -------------------------------------------------

    summary = ET.SubElement(root, "scan_summary")

    ET.SubElement(
        summary,
        "hosts_found"
    ).text = str(hosts_found)

    ET.SubElement(
        summary,
        "open_ports"
    ).text = str(open_ports)

    ET.SubElement(
        summary,
        "services_found"
    ).text = str(services_found)

    # -------------------------------------------------
    # SECURITY ASSESSMENT
    # -------------------------------------------------

    assessment = ET.SubElement(
        root,
        "security_assessment"
    )

    ET.SubElement(
        assessment,
        "high"
    ).text = str(high_count)

    ET.SubElement(
        assessment,
        "medium"
    ).text = str(medium_count)

    ET.SubElement(
        assessment,
        "info"
    ).text = str(info_count)

    # -------------------------------------------------
    # SECURITY RECOMMENDATIONS
    # -------------------------------------------------

    recommendations_element = ET.SubElement(
        root,
        "security_recommendations"
    )

    for recommendation in recommendations:

        finding = ET.SubElement(
            recommendations_element,
            "finding"
        )

        ET.SubElement(
            finding,
            "severity"
        ).text = str(
            recommendation["severity"]
        )

        ET.SubElement(
            finding,
            "port"
        ).text = str(
            recommendation["port"]
        )

        ET.SubElement(
            finding,
            "service"
        ).text = str(
            recommendation["service"]
        )

        ET.SubElement(
            finding,
            "message"
        ).text = str(
            recommendation["message"]
        )

        ET.SubElement(
            finding,
            "recommendation"
        ).text = str(
            recommendation["recommendation"]
        )

    # -------------------------------------------------
    # PORT RESULTS
    # -------------------------------------------------

    port_results = ET.SubElement(
        root,
        "port_results"
    )

    for result in results:

        port = ET.SubElement(
            port_results,
            "port"
        )

        ET.SubElement(
            port,
            "host"
        ).text = str(
            result["host"]
        )

        ET.SubElement(
            port,
            "protocol"
        ).text = str(
            result["protocol"]
        )

        ET.SubElement(
            port,
            "number"
        ).text = str(
            result["port"]
        )

        ET.SubElement(
            port,
            "state"
        ).text = str(
            result["state"]
        )

        ET.SubElement(
            port,
            "service"
        ).text = str(
            result["service"]
        )

        ET.SubElement(
            port,
            "product"
        ).text = str(
            result["product"]
        )

        ET.SubElement(
            port,
            "version"
        ).text = str(
            result["version"]
        )

    # -------------------------------------------------
    # WRITE XML FILE
    # -------------------------------------------------

    tree = ET.ElementTree(root)

    ET.indent(
        tree,
        space="    "
    )

    tree.write(
        output_path,
        encoding="utf-8",
        xml_declaration=True
    )