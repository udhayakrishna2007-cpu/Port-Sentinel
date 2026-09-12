import threading
import uuid
scan_jobs = {}
import os
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from scanner.validator import validate_target
from scanner.nmap_scanner import (
    scan_target,
    get_scan_type_name,
    SCAN_TYPES
)

from recommendations import analyze_results
from pdf_report import generate_pdf_report
from xml_report import generate_xml_report
from email_report import send_email_report

from database import (
    create_database,

    create_user,
    get_user_by_email,
    get_user_by_username,
    get_user_by_id,

    save_scan,
    save_scan_results,

    get_scans,
    get_scan_by_id,
    get_scan_results,
    get_recent_scans,
    get_total_scans,
    get_total_open_ports,
    get_latest_scan
)


# ---------------------------------------------------------
# Environment
# ---------------------------------------------------------

load_dotenv()


MAIL_USERNAME = os.getenv(
    "MAIL_USERNAME"
)

MAIL_PASSWORD = os.getenv(
    "MAIL_PASSWORD"
)

MAIL_SERVER = os.getenv(
    "MAIL_SERVER",
    "smtp.gmail.com"
)

MAIL_PORT = int(
    os.getenv(
        "MAIL_PORT",
        "587"
    )
)


# ---------------------------------------------------------
# Flask Application
# ---------------------------------------------------------

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not configured."
    )

create_database()


# ---------------------------------------------------------
# Authentication Helper
# ---------------------------------------------------------

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


# ---------------------------------------------------------
# Assessment
# ---------------------------------------------------------

def calculate_assessment(results):

    recommendations = analyze_results(
        results
    )

    high_count = sum(
        1
        for recommendation in recommendations
        if recommendation["severity"] == "High"
    )

    medium_count = sum(
        1
        for recommendation in recommendations
        if recommendation["severity"] == "Medium"
    )

    info_count = sum(
        1
        for recommendation in recommendations
        if recommendation["severity"] == "Info"
    )

    hosts_found = len(
        set(
            result.get("host")
            for result in results
            if result.get("host")
        )
    )

    open_ports = sum(
        1
        for result in results
        if result.get("port") is not None
        and result.get("state") == "open"
    )

    services_found = len(
        set(
            result.get("service")
            for result in results
            if result.get("service")
        )
    )

    if high_count > 0:

        security_status = "High Priority"
        security_status_class = "high"

    elif medium_count > 0:

        security_status = "Attention Required"
        security_status_class = "medium"

    elif info_count > 0:

        security_status = "Informational"
        security_status_class = "info"

    else:

        security_status = "No Immediate Findings"
        security_status_class = "safe"

    return {
        "recommendations": recommendations,
        "high_count": high_count,
        "medium_count": medium_count,
        "info_count": info_count,
        "hosts_found": hosts_found,
        "open_ports": open_ports,
        "services_found": services_found,
        "security_status": security_status,
        "security_status_class": security_status_class
    }


# ---------------------------------------------------------
# Host List Builder
# ---------------------------------------------------------
# Shared by run_scan_job (live scans) and the history / report
# routes (past scans) so results.html / report.html always get
# the same "hosts" shape regardless of which route rendered them.

def build_host_list(results):

    hosts = []
    seen_hosts = set()

    for result in results:

        host = result.get("host")

        if not host:
            continue

        if host in seen_hosts:
            continue

        seen_hosts.add(host)

        hosts.append({
            "host": host,
            "hostname": result.get("hostname", ""),
            "host_state": result.get("host_state", "unknown"),
            "mac": result.get("mac", ""),
            "vendor": result.get("vendor", ""),
            "os_name": result.get("os_name", ""),
            "os_family": result.get("os_family", ""),
            "os_generation": result.get("os_generation", ""),
            "os_accuracy": result.get("os_accuracy", "")
        })

    return hosts


# ---------------------------------------------------------
# Report Preparation
# ---------------------------------------------------------

def prepare_report_data(
    scan,
    results
):

    assessment = calculate_assessment(
        results
    )

    scan_type = "tcp"

    if scan and len(scan) >= 4:

        scan_type = (
            scan[3]
            or "tcp"
        )

    return {

        "scan": scan,

        "results": results,

        "hosts": build_host_list(results),

        "scan_type": scan_type,

        "scan_type_name": get_scan_type_name(
            scan_type
        ),

        "recommendations":
            assessment["recommendations"],

        "high_count":
            assessment["high_count"],

        "medium_count":
            assessment["medium_count"],

        "info_count":
            assessment["info_count"],

        "hosts_found":
            assessment["hosts_found"],

        "open_ports":
            assessment["open_ports"],

        "services_found":
            assessment["services_found"],

        "security_status":
            assessment["security_status"],

        "security_status_class":
            assessment[
                "security_status_class"
            ]
    }


# ---------------------------------------------------------
# Login
# ---------------------------------------------------------
# NOTE: assumes get_user_by_email() returns a row shaped like
# (id, full_name, username, email, password_hash, created_at) —
# i.e. the same column order used in create_user() above.
# Adjust the indices below if your database.py returns a
# different shape (e.g. a dict or a differently-ordered tuple).

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username:
            flash("Username is required.", "error")
            return render_template("login.html")

        if not password:
            flash("Password is required.", "error")
            return render_template("login.html")

        user = get_user_by_username(username)

        if not user:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        if not check_password_hash(user[4], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["user_id"] = user[0]
        session["full_name"] = user[1]
        session["username"] = user[2]

        flash("Login successful. Welcome back!", "success")

        return redirect(url_for("home"))

    return render_template("login.html")

# ---------------------------------------------------------

# Create Account

# ---------------------------------------------------------

@app.route(
"/register",
methods=["GET", "POST"]
)

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # -------------------------------------------------
        # Validation
        # -------------------------------------------------

        if not username:
            flash("Username is required.", "error")
            return render_template("register.html")

        if not email:
            flash("Email address is required.", "error")
            return render_template("register.html")

        if not password:
            flash("Password is required.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash(
                "Password must be at least 8 characters.",
                "error"
            )
            return render_template("register.html")

        if not confirm_password:
            flash(
                "Please confirm your password.",
                "error"
            )
            return render_template("register.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )
            return render_template("register.html")

        # -------------------------------------------------
        # Duplicate Checks
        # -------------------------------------------------

        if get_user_by_email(email):
            flash(
                "An account with that email already exists.",
                "error"
            )
            return render_template("register.html")

        if get_user_by_username(username):
            flash(
                "That username is already taken.",
                "error"
            )
            return render_template("register.html")

        # -------------------------------------------------
        # Password Hash
        # -------------------------------------------------

        password_hash = generate_password_hash(password)

        created_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # -------------------------------------------------
        # Create User
        #
        # Database still expects:
        # full_name, username, email, password_hash, created_at
        #
        # We use username as full_name internally for now.
        # -------------------------------------------------

        user_id = create_user(
            username,
            username,
            email,
            password_hash,
            created_at
        )

        if not user_id:
            flash(
                "Unable to create the account. Please try again.",
                "error"
            )
            return render_template("register.html")

        # -------------------------------------------------
        # Success
        # -------------------------------------------------

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")




# ---------------------------------------------------------
# Logout
# ---------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ---------------------------------------------------------
# Home / Dashboard
# ---------------------------------------------------------

@app.route("/")
@login_required
def home():

    user_id = session["user_id"]

    total_scans = get_total_scans(
        user_id
    )

    total_open_ports = get_total_open_ports(
        user_id
    )

    latest_scan = get_latest_scan(
        user_id
    )

    recent_scans = get_recent_scans(
        user_id
    )

    return render_template(
        "index.html",

        total_scans=total_scans,

        total_open_ports=total_open_ports,

        latest_scan=latest_scan,

        recent_scans=recent_scans
    )


# ---------------------------------------------------------
# Scan History
# ---------------------------------------------------------

@app.route("/history")
@login_required
def history():

    user_id = session["user_id"]

    scans = get_scans(
        user_id
    )

    return render_template(
        "history.html",
        scans=scans
    )


# ---------------------------------------------------------
# Historical Scan
# ---------------------------------------------------------

@app.route(
    "/history/<int:scan_id>"
)
@login_required
def scan_history(scan_id):

    user_id = session["user_id"]

    scan = get_scan_by_id(
        scan_id,
        user_id
    )

    if not scan:

        return render_template(
            "error.html",
            message="Scan history record not found."
        )

    results = get_scan_results(
        scan_id
    )

    report_data = prepare_report_data(
        scan,
        results
    )

    return render_template(
        "results.html",

        target=scan[1],

        scan_id=scan_id,

        scan_type=report_data[
            "scan_type"
        ],

        scan_type_name=report_data[
            "scan_type_name"
        ],

        results=results,

        hosts=report_data[
            "hosts"
        ],

        recommendations=report_data[
            "recommendations"
        ],

        high_count=report_data[
            "high_count"
        ],

        medium_count=report_data[
            "medium_count"
        ],

        info_count=report_data[
            "info_count"
        ],

        security_status=report_data[
            "security_status"
        ],

        security_status_class=report_data[
            "security_status_class"
        ],

        hosts_found=report_data[
            "hosts_found"
        ],

        open_ports=report_data[
            "open_ports"
        ],

        services_found=report_data[
            "services_found"
        ],

        report_data=report_data
    )

def run_scan_job(job_id, target, scan_type, user_id):
    try:

        results = scan_target(
            target,
            scan_type
        )

        if not results:
            scan_jobs[job_id] = {
                "status": "error",
                "message": (
                    "The scan completed, but Nmap did not return "
                    "any results for this target."
                )
            }
            return

        assessment = calculate_assessment(
            results
        )

        scan_date = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        scan_id = save_scan(
            target,
            scan_date,
            scan_type,
            user_id
        )

        save_scan_results(
            scan_id,
            results
        )

        hosts = build_host_list(results)

        report_data = {

            "target": target,

            "scan_id": scan_id,

            "scan_type": scan_type,

            "scan_type_name":
                get_scan_type_name(
                    scan_type
                ),

            "results": results,

            "hosts": hosts,

            "recommendations":
                assessment["recommendations"],

            "summary": {

                "hosts":
                    assessment["hosts_found"],

                "open_ports":
                    assessment["open_ports"],

                "services":
                    assessment["services_found"]
            },

            "assessment": {

                "high":
                    assessment["high_count"],

                "medium":
                    assessment["medium_count"],

                "info":
                    assessment["info_count"],

                "status":
                    assessment["security_status"],

                "status_class":
                    assessment["security_status_class"]
            }
        }

        scan_jobs[job_id] = {

            "status": "complete",

            "scan_id": scan_id,

            "target": target,

            "scan_type": scan_type,

            "scan_type_name":
                get_scan_type_name(
                    scan_type
                ),

            "results": results,

            "hosts": hosts,

            "recommendations":
                assessment["recommendations"],

            "high_count":
                assessment["high_count"],

            "medium_count":
                assessment["medium_count"],

            "info_count":
                assessment["info_count"],

            "security_status":
                assessment["security_status"],

            "security_status_class":
                assessment["security_status_class"],

            "hosts_found":
                assessment["hosts_found"],

            "open_ports":
                assessment["open_ports"],

            "services_found":
                assessment["services_found"],

            "report_data":
                report_data
        }

    except RuntimeError as error:

        print(f"[SCAN ERROR] {error}")

        scan_jobs[job_id] = {
            "status": "error",
            "message": "The scan could not be completed. Please try again."
        }

    except Exception as error:

        print(f"[UNEXPECTED SCANNER ERROR] {error}")

        scan_jobs[job_id] = {
            "status": "error",
            "message": "An unexpected error occurred while scanning. Please try again."
        }

@app.route(
    "/scan",
    methods=["POST"]
)
@login_required
def scan():

    target = request.form.get(
        "target",
        ""
    ).strip()

    scan_type = request.form.get(
        "scan_type",
        "tcp"
    ).strip().lower()

    if not target:

        return render_template(
            "error.html",
            message=(
                "Target is required. "
                "Please enter a local or private network target."
            )
        )

    if not validate_target(target):

        return render_template(
            "error.html",
            message=(
                "Invalid target. "
                "Please enter a valid local or private network target."
            )
        )

    if scan_type not in SCAN_TYPES:

        return render_template(
            "error.html",
            message="Invalid scan type."
        )

    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "status": "running"
    }

    thread = threading.Thread(
        target=run_scan_job,
        args=(
            job_id,
            target,
            scan_type,
            session["user_id"]
        ),
        daemon=True
    )

    thread.start()

    return render_template(
        "loading.html",
        target=target,
        scan_type=scan_type,
        scan_type_name=get_scan_type_name(
            scan_type
        ),
        job_id=job_id
    )

@app.route(
    "/scan-status/<job_id>"
)
@login_required
def scan_status(job_id):

    job = scan_jobs.get(job_id)

    if not job:

        return {
            "status": "error",
            "message": "Scan job not found."
        }, 404

    return {
        "status": job.get(
            "status",
            "running"
        )
    }

@app.route(
    "/scan-results/<job_id>"
)
@login_required
def scan_results(job_id):

    job = scan_jobs.get(job_id)

    if not job:

        return render_template(
            "error.html",
            message="Scan job not found."
        )

    if job.get("status") == "error":

        return render_template(
            "error.html",
            message=job.get(
                "message",
                "The scan failed."
            )
        )

    if job.get("status") != "complete":

        return render_template(
            "error.html",
            message="The scan is still running."
        )

    return render_template(
        "results.html",

        target=job["target"],

        scan_id=job["scan_id"],

        scan_type=job["scan_type"],

        scan_type_name=job["scan_type_name"],

        results=job["results"],

        hosts=job["hosts"],

        recommendations=job["recommendations"],

        high_count=job["high_count"],

        medium_count=job["medium_count"],

        info_count=job["info_count"],

        security_status=job["security_status"],

        security_status_class=job[
            "security_status_class"
        ],

        hosts_found=job["hosts_found"],

        open_ports=job["open_ports"],

        services_found=job["services_found"],

        report_data=job["report_data"]
    )
# ---------------------------------------------------------
# Full Security Report
# ---------------------------------------------------------

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def report(scan_id):

    user_id = session["user_id"]

    scan = get_scan_by_id(
        scan_id,
        user_id
    )

    if not scan:

        return render_template(
            "error.html",
            message="Scan report not found."
        )

    results = get_scan_results(
        scan_id
    )

    report_data = prepare_report_data(
        scan,
        results
    )

    return render_template(
        "report.html",

        scan=scan,

        scan_id=scan_id,

        scan_type=report_data[
            "scan_type"
        ],

        scan_type_name=report_data[
            "scan_type_name"
        ],

        results=results,

        hosts=report_data[
            "hosts"
        ],

        recommendations=report_data[
            "recommendations"
        ],

        high_count=report_data[
            "high_count"
        ],

        medium_count=report_data[
            "medium_count"
        ],

        info_count=report_data[
            "info_count"
        ],

        hosts_found=report_data[
            "hosts_found"
        ],

        open_ports=report_data[
            "open_ports"
        ],

        services_found=report_data[
            "services_found"
        ],

        security_status=report_data[
            "security_status"
        ],

        security_status_class=report_data[
            "security_status_class"
        ]
    )


# ---------------------------------------------------------
# PDF Report
# ---------------------------------------------------------

@app.route(
    "/report/<int:scan_id>/pdf"
)
@login_required
def download_pdf_report(scan_id):

    user_id = session["user_id"]

    scan = get_scan_by_id(
        scan_id,
        user_id
    )

    if not scan:

        return render_template(
            "error.html",
            message="Scan not found."
        )

    results = get_scan_results(
        scan_id
    )

    report_data = prepare_report_data(
        scan,
        results
    )

    filename = (
        f"port_sentinel_report_{scan_id}.pdf"
    )

    generate_pdf_report(
        filename,

        scan,

        results,

        report_data[
            "recommendations"
        ],

        report_data[
            "high_count"
        ],

        report_data[
            "medium_count"
        ],

        report_data[
            "info_count"
        ],

        report_data[
            "hosts_found"
        ],

        report_data[
            "open_ports"
        ],

        report_data[
            "services_found"
        ],

        report_data[
            "security_status"
        ]
    )

    return send_file(
        filename,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


# ---------------------------------------------------------
# XML Report
# ---------------------------------------------------------

@app.route(
    "/report/<int:scan_id>/xml"
)
@login_required
def download_xml_report(scan_id):

    user_id = session["user_id"]

    scan = get_scan_by_id(
        scan_id,
        user_id
    )

    if not scan:

        return render_template(
            "error.html",
            message="Scan not found."
        )

    results = get_scan_results(
        scan_id
    )

    report_data = prepare_report_data(
        scan,
        results
    )

    filename = (
        f"port_sentinel_report_{scan_id}.xml"
    )

    generate_xml_report(
        filename,

        scan,

        results,

        report_data[
            "recommendations"
        ],

        report_data[
            "high_count"
        ],

        report_data[
            "medium_count"
        ],

        report_data[
            "info_count"
        ],

        report_data[
            "hosts_found"
        ],

        report_data[
            "open_ports"
        ],

        report_data[
            "services_found"
        ],

        report_data[
            "security_status"
        ]
    )

    return send_file(
        filename,
        as_attachment=True,
        download_name=filename,
        mimetype="application/xml"
    )


# ---------------------------------------------------------
# Email Report
# ---------------------------------------------------------

@app.route(
    "/report/<int:scan_id>/email",
    methods=["POST"]
)
@login_required
def email_report(scan_id):

    user_id = session["user_id"]

    scan = get_scan_by_id(
        scan_id,
        user_id
    )

    if not scan:

        return render_template(
            "error.html",
            message="Scan not found."
        )

    recipient_email = request.form.get(
        "recipient_email",
        ""
    ).strip()

    if not recipient_email:

        return render_template(
            "error.html",
            message="Recipient email is required."
        )

    results = get_scan_results(
        scan_id
    )

    report_data = prepare_report_data(
        scan,
        results
    )

    filename = (
        f"port_sentinel_report_{scan_id}.pdf"
    )

    generate_pdf_report(
        filename,

        scan,

        results,

        report_data[
            "recommendations"
        ],

        report_data[
            "high_count"
        ],

        report_data[
            "medium_count"
        ],

        report_data[
            "info_count"
        ],

        report_data[
            "hosts_found"
        ],

        report_data[
            "open_ports"
        ],

        report_data[
            "services_found"
        ],

        report_data[
            "security_status"
        ]
    )

    send_email_report(
        recipient_email,

        (
            "Port Sentinel Security Report "
            f"— Scan #{scan_id}"
        ),

        (
            "Attached is the Port Sentinel security "
            f"assessment report for scan #{scan_id}.\n\n"

            f"Target: {scan[1]}\n"

            f"Scan Type: "
            f"{report_data['scan_type_name']}\n"

            f"Security Status: "
            f"{report_data['security_status']}\n"
        ),

        filename
    )

    return render_template(
        "email_success.html",
        scan_id=scan_id
    )


# ---------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=os.getenv("FLASK_DEBUG", "False").lower() == "true"
    )