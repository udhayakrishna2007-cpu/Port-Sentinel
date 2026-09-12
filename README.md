# 🔐 Port Sentinel

Port Sentinel is a Flask-based network security scanning application designed to discover open ports, identify running services, assess security findings, and generate security reports for authorized local and private-network targets.

The application provides a web-based interface with user authentication, scan history, security recommendations, and multiple report formats.

---

## ✨ Features

- 🔐 User registration and login
- 🔒 Password hashing and session-based authentication
- 🎯 Local and private-network target validation
- 🔍 Multiple Nmap scan modes
- ⚡ Background scan execution
- 📊 Scan result summaries
- 🖥️ Host information and operating-system detection
- 🔌 Open-port and service discovery
- 🛡️ Security assessment and severity classification
- ⚠️ High, Medium, and Informational findings
- 💡 Security recommendations
- 🕘 Scan history
- 📄 PDF security reports
- 📋 XML security reports
- 📧 Email delivery of PDF reports
- 🎨 Responsive web interface
- 🔐 Environment-based configuration for secrets

---

## 🔍 Scan Types

Port Sentinel currently supports the following scan types:

| Scan Type | Description |
|---|---|
| TCP Scan | Performs a TCP-based port scan |
| UDP Scan | Performs a UDP-based port scan |
| SYN Scan | Performs a SYN-based scan |
| Service Version Detection | Attempts to identify running service and version information |
| OS Detection | Attempts to identify the target operating system |
| Aggressive Scan | Performs an aggressive Nmap scan combining multiple detection techniques |

> Scan availability and results may depend on the operating system, Nmap configuration, network conditions, and required privileges.

---

## 🛡️ Security Assessment

After a scan completes, Port Sentinel analyzes the discovered results and classifies findings into:

- 🔴 **High**
- 🟠 **Medium**
- 🔵 **Informational**

The application generates security recommendations based on detected services and ports.

The assessment also provides summary information including:

- Number of hosts discovered
- Number of open ports
- Number of services identified
- Security status
- Number of findings by severity

---

## 📊 Scan Results

The results interface can display information such as:

- Host
- Protocol
- Port
- State
- Service
- Product
- Version

Where available, host information may also include:

- Hostname
- Host state
- Operating system
- OS family
- OS generation
- OS detection accuracy
- MAC address
- Vendor

---

## 📄 Security Reports

Port Sentinel provides multiple ways to work with completed scan results.

### PDF Reports

Generate a structured security assessment report containing scan information, findings, recommendations, and summary statistics.

### XML Reports

Export scan information in XML format for structured processing or integration with other tools.

### Email Reports

A generated PDF security report can also be sent to a specified recipient through the configured email server.

---

## 🕘 Scan History

Authenticated users can access previously completed scans through the Scan History section.

Historical scans can be reviewed and their associated security results and reports can be accessed again.

---

## 🧰 Technology Stack

### Backend

- Python
- Flask
- python-nmap
- python-dotenv

### Security

- Werkzeug password hashing
- Session-based authentication
- Target validation

### Reporting

- ReportLab
- Pillow
- XML generation
- Email/SMTP

### Server

- Flask development server
- Waitress dependency for WSGI deployment

### Frontend

- HTML
- CSS
- JavaScript
- Jinja2 templates

### Database

- SQLite

---

## 📁 Project Structure

```text
Port-Sentinel/
│
├── scanner/
│   ├── __init__.py
│   ├── nmap_scanner.py
│   └── validator.py
│
├── static/
│   └── style.css
│
├── templates/
│   ├── base.html
│   ├── email_success.html
│   ├── error.html
│   ├── history.html
│   ├── index.html
│   ├── loading.html
│   ├── login.html
│   ├── register.html
│   ├── report.html
│   └── results.html
│
├── app.py
├── database.py
├── email_report.py
├── pdf_report.py
├── recommendations.py
├── requirements.txt
├── scanner_test.py
└── xml_report.py

## 🧪 Testing

The repository includes a simple scanner test script:

```text
scanner_test.py