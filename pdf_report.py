from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_pdf_report(
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

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=18,
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    story = []

    # -------------------------------------------------
    # HEADER
    # -------------------------------------------------

    story.append(
        Paragraph(
            "PORT SENTINEL",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            heading_style
        )
    )

    story.append(Spacer(1, 5))

    report_metadata = [
        ["Target", str(scan[1])],
        ["Scan Date", str(scan[2])],
        ["Scan ID", f"#{scan[0]}"],
        ["Security Status", str(security_status)]
    ]

    metadata_table = Table(
        report_metadata,
        colWidths=[45 * mm, 130 * mm]
    )

    metadata_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(metadata_table)
    story.append(Spacer(1, 15))

    # -------------------------------------------------
    # OVERVIEW
    # -------------------------------------------------

    story.append(
        Paragraph(
            "Assessment Overview",
            heading_style
        )
    )

    if open_ports > 0:

        overview_text = (
            f"The scan identified <b>{open_ports}</b> open "
            f"port(s) across <b>{hosts_found}</b> host(s)."
        )

    else:

        overview_text = (
            "The scan completed successfully and did not "
            "identify any open ports on the target."
        )

    story.append(
        Paragraph(
            overview_text,
            body_style
        )
    )

    story.append(Spacer(1, 10))

    # -------------------------------------------------
    # SCAN SUMMARY
    # -------------------------------------------------

    story.append(
        Paragraph(
            "Scan Summary",
            heading_style
        )
    )

    summary_data = [
        ["Hosts", "Open Ports", "Services"],
        [
            str(hosts_found),
            str(open_ports),
            str(services_found)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[58 * mm, 58 * mm, 58 * mm]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(summary_table)

    # -------------------------------------------------
    # SECURITY ASSESSMENT
    # -------------------------------------------------

    story.append(
        Paragraph(
            "Security Assessment",
            heading_style
        )
    )

    assessment_data = [
        ["High", "Medium", "Info"],
        [
            str(high_count),
            str(medium_count),
            str(info_count)
        ]
    ]

    assessment_table = Table(
        assessment_data,
        colWidths=[58 * mm, 58 * mm, 58 * mm]
    )

    assessment_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(assessment_table)

    story.append(
        Spacer(1, 5)
    )

    story.append(
        Paragraph(
            f"<b>Status:</b> {security_status}",
            body_style
        )
    )

    # -------------------------------------------------
    # SECURITY FINDINGS / RECOMMENDATIONS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "Security Recommendations",
            heading_style
        )
    )

    if recommendations:

        for recommendation in recommendations:

            finding_text = (
                f"<b>[{recommendation['severity']}] "
                f"{recommendation['service']} — "
                f"Port {recommendation['port']}</b><br/>"
                f"{recommendation['message']}<br/><br/>"
                f"<b>Recommendation:</b> "
                f"{recommendation['recommendation']}"
            )

            story.append(
                Paragraph(
                    finding_text,
                    body_style
                )
            )

            story.append(
                Spacer(1, 8)
            )

    else:

        story.append(
            Paragraph(
                "No security findings were identified during the assessment.",
                body_style
            )
        )

    # -------------------------------------------------
    # PORT RESULTS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "Technical Port Results",
            heading_style
        )
    )

    if results:

        table_data = [
            [
                "Host",
                "Protocol",
                "Port",
                "State",
                "Service",
                "Product",
                "Version"
            ]
        ]

        for result in results:

            table_data.append([
                str(result["host"]),
                str(result["protocol"]),
                str(result["port"]),
                str(result["state"]),
                str(result["service"]),
                str(result["product"]),
                str(result["version"])
            ])

        results_table = Table(
            table_data,
            repeatRows=1,
            colWidths=[
                25 * mm,
                18 * mm,
                15 * mm,
                18 * mm,
                25 * mm,
                35 * mm,
                35 * mm
            ]
        )

        results_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4)
            ])
        )

        story.append(results_table)

    else:

        story.append(
            Paragraph(
                "No open ports were found.",
                body_style
            )
        )

    # -------------------------------------------------
    # BUILD PDF
    # -------------------------------------------------

    document.build(story)