from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

from database import (
    create_database,

    add_threat,
    get_threats,

    add_log,
    get_logs,

    add_incident,
    get_incidents,
    update_incident_status,

    monitor_ip,
    get_monitored_ips,
    get_suspicious_ips,
    get_blocked_ips
)


app = Flask(__name__)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

create_database()


# =========================================================
# THREAT DETECTION ENGINE
# =========================================================

def detect_threat(event):

    threat_type = "None"

    severity = "LOW"

    description = "Normal security activity."


    failed_attempts = event.get(
        "failed_attempts",
        0
    )


    event_type = event.get(
        "event_type",
        ""
    ).lower()


    ip_address = event.get(
        "ip_address",
        ""
    )


    status = event.get(
        "status",
        "UNKNOWN"
    )


    # =====================================================
    # BRUTE FORCE DETECTION
    # =====================================================

    if failed_attempts >= 5:

        threat_type = "Brute Force Attack"

        severity = "HIGH"

        description = (
            "Multiple failed login attempts detected."
        )


    # =====================================================
    # SUSPICIOUS LOGIN DETECTION
    # =====================================================

    elif event_type == "suspicious_login":

        threat_type = "Suspicious Login"

        severity = "MEDIUM"

        description = (
            "Suspicious login activity detected."
        )


    # =====================================================
    # MALWARE DETECTION
    # =====================================================

    elif event_type == "malware":

        threat_type = "Malware Activity"

        severity = "CRITICAL"

        description = (
            "Potential malware activity detected."
        )


    # =====================================================
    # SQL INJECTION DETECTION
    # =====================================================

    elif event_type == "sql_injection":

        threat_type = "SQL Injection Attack"

        severity = "CRITICAL"

        description = (
            "Potential SQL injection attack detected."
        )


    # =====================================================
    # RESULT
    # =====================================================

    return {

        "threat_type": threat_type,

        "severity": severity,

        "description": description,

        "ip_address": ip_address,

        "event_type": event_type,

        "status": status,

        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }


# =========================================================
# IP THREAT LEVEL
# =========================================================

def get_ip_status(result):

    severity = result["severity"]


    if severity == "CRITICAL":

        return "Blocked", "High"


    elif severity == "HIGH":

        return "Suspicious", "High"


    elif severity == "MEDIUM":

        return "Suspicious", "Medium"


    else:

        return "Allowed", "Low"


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def home():

    threats = get_threats()

    incidents_data = get_incidents()

    logs_data = get_logs()

    monitored_ips = get_monitored_ips()

    suspicious_ips = get_suspicious_ips()

    blocked_ips = get_blocked_ips()


    total_threats = len(threats)


    high_threats = sum(

        1

        for threat in threats

        if threat["severity"] == "HIGH"

    )


    critical_threats = sum(

        1

        for threat in threats

        if threat["severity"] == "CRITICAL"

    )


    total_incidents = len(
        incidents_data
    )


    total_logs = len(
        logs_data
    )


    total_ips = len(
        monitored_ips
    )


    suspicious_ip_count = len(
        suspicious_ips
    )


    blocked_ip_count = len(
        blocked_ips
    )


    return render_template(

        "index.html",

        total_threats=total_threats,

        high_threats=high_threats,

        critical_threats=critical_threats,

        total_incidents=total_incidents,

        total_logs=total_logs,

        total_ips=total_ips,

        suspicious_ip_count=suspicious_ip_count,

        blocked_ip_count=blocked_ip_count

    )


# =========================================================
# THREATS PAGE
# =========================================================

@app.route("/threats")
def threats():

    threats_data = get_threats()


    return render_template(

        "threats.html",

        threats=threats_data

    )


# =========================================================
# TEST THREAT
# =========================================================

@app.route("/test-threat")
def test_threat():

    event = {

        "event_type": "login",

        "failed_attempts": 5,

        "ip_address": "192.168.1.100",

        "status": "FAILED"

    }


    result = detect_threat(event)


    if result["threat_type"] != "None":

        add_threat(

            result["threat_type"],

            result["severity"],

            result["description"],

            result["time"]

        )


    ip_status, threat_level = get_ip_status(
        result
    )


    monitor_ip(

        event["ip_address"],

        ip_status,

        threat_level,

        result["time"]

    )


    if result["threat_type"] != "None":

        add_incident(

            result["threat_type"],

            result["severity"],

            result["description"],

            "OPEN",

            result["time"]

        )


    return redirect(
        url_for("threats")
    )


# =========================================================
# LOGS PAGE
# =========================================================

@app.route("/logs")
def logs():

    logs_data = get_logs()


    return render_template(

        "logs.html",

        logs=logs_data

    )


# =========================================================
# TEST SECURITY LOG
# =========================================================

@app.route("/test-log")
def test_log():

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    event = {

        "event_type": "login",

        "failed_attempts": 5,

        "ip_address": "192.168.1.100",

        "status": "FAILED"

    }


    add_log(

        event["event_type"],

        event["ip_address"],

        event["status"],

        current_time

    )


    result = detect_threat(event)


    ip_status, threat_level = get_ip_status(
        result
    )


    monitor_ip(

        event["ip_address"],

        ip_status,

        threat_level,

        current_time

    )


    if result["threat_type"] != "None":

        add_threat(

            result["threat_type"],

            result["severity"],

            result["description"],

            result["time"]

        )


        add_incident(

            result["threat_type"],

            result["severity"],

            result["description"],

            "OPEN",

            result["time"]

        )


    return redirect(
        url_for("logs")
    )


# =========================================================
# SECURITY EVENT INPUT
# =========================================================

@app.route(
    "/security-event",
    methods=["GET", "POST"]
)
def security_event():

    result = None


    if request.method == "GET":

        return render_template(

            "security_event.html",

            result=None

        )


    event_type = request.form.get(

        "event_type",

        ""

    ).strip()


    ip_address = request.form.get(

        "ip_address",

        ""

    ).strip()


    try:

        failed_attempts = int(

            request.form.get(

                "failed_attempts",

                0

            )

        )

    except ValueError:

        failed_attempts = 0


    status = request.form.get(

        "status",

        "UNKNOWN"

    ).strip()


    if not ip_address:

        ip_address = request.remote_addr


    event = {

        "event_type": event_type,

        "failed_attempts": failed_attempts,

        "ip_address": ip_address,

        "status": status

    }


    current_time = datetime.now().strftime(

        "%Y-%m-%d %H:%M:%S"

    )


    add_log(

        event_type,

        ip_address,

        status,

        current_time

    )


    result = detect_threat(event)


    ip_status, threat_level = get_ip_status(

        result

    )


    monitor_ip(

        ip_address,

        ip_status,

        threat_level,

        current_time

    )


    if result["threat_type"] != "None":

        add_threat(

            result["threat_type"],

            result["severity"],

            result["description"],

            result["time"]

        )


        add_incident(

            result["threat_type"],

            result["severity"],

            result["description"],

            "OPEN",

            result["time"]

        )


    return render_template(

        "security_event.html",

        result=result

    )


# =========================================================
# IP MONITORING PAGE
# =========================================================

@app.route("/ip-monitoring")
def ip_monitoring():

    monitored_ips = get_monitored_ips()

    suspicious_ips = get_suspicious_ips()

    blocked_ips = get_blocked_ips()


    return render_template(

        "ip_monitoring.html",

        ips=monitored_ips,

        suspicious_ips=suspicious_ips,

        blocked_ips=blocked_ips,

        total_ips=len(monitored_ips),

        suspicious_count=len(suspicious_ips),

        blocked_count=len(blocked_ips)

    )


# =========================================================
# TEST IP MONITORING
# =========================================================

@app.route("/test-ip")
def test_ip():

    current_time = datetime.now().strftime(

        "%Y-%m-%d %H:%M:%S"

    )


    ip_address = "192.168.1.200"


    event = {

        "event_type": "suspicious_login",

        "failed_attempts": 3,

        "ip_address": ip_address,

        "status": "SUSPICIOUS"

    }


    result = detect_threat(event)


    ip_status, threat_level = get_ip_status(

        result

    )


    monitor_ip(

        ip_address,

        ip_status,

        threat_level,

        current_time

    )


    add_log(

        event["event_type"],

        ip_address,

        event["status"],

        current_time

    )


    if result["threat_type"] != "None":

        add_threat(

            result["threat_type"],

            result["severity"],

            result["description"],

            result["time"]

        )


        add_incident(

            result["threat_type"],

            result["severity"],

            result["description"],

            "OPEN",

            result["time"]

        )


    return redirect(
        url_for("ip_monitoring")
    )


# =========================================================
# INCIDENTS PAGE
# =========================================================

@app.route("/incidents")
def incidents():

    incidents_data = get_incidents()


    return render_template(

        "incidents.html",

        incidents=incidents_data

    )


# =========================================================
# UPDATE INCIDENT STATUS
# =========================================================

@app.route(
    "/update-incident/<int:incident_id>",
    methods=["POST"]
)
def update_incident(incident_id):

    status = request.form.get(
        "status",
        "OPEN"
    ).strip().upper()


    valid_statuses = [

        "OPEN",

        "INVESTIGATING",

        "RESOLVED",

        "CLOSED"

    ]


    if status not in valid_statuses:

        return redirect(
            url_for("incidents")
        )


    update_incident_status(

        incident_id,

        status

    )


    return redirect(
        url_for("incidents")
    )


# =========================================================
# TEST INCIDENT
# =========================================================

@app.route("/test-incident")
def test_incident():

    current_time = datetime.now().strftime(

        "%Y-%m-%d %H:%M:%S"

    )


    add_incident(

        "Brute Force Attack",

        "HIGH",

        "Multiple failed login attempts detected.",

        "OPEN",

        current_time

    )


    return redirect(
        url_for("incidents")
    )


# =========================================================
# REPORTS
# =========================================================

@app.route("/reports")
def reports():

    threats_data = get_threats()

    logs_data = get_logs()

    incidents_data = get_incidents()

    monitored_ips = get_monitored_ips()

    suspicious_ips = get_suspicious_ips()

    blocked_ips = get_blocked_ips()


    total_threats = len(
        threats_data
    )


    critical_threats = sum(

        1

        for threat in threats_data

        if threat["severity"] == "CRITICAL"

    )


    high_threats = sum(

        1

        for threat in threats_data

        if threat["severity"] == "HIGH"

    )


    total_logs = len(
        logs_data
    )


    total_incidents = len(
        incidents_data
    )


    total_ips = len(
        monitored_ips
    )


    suspicious_ip_count = len(
        suspicious_ips
    )


    blocked_ip_count = len(
        blocked_ips
    )


    return render_template(

        "reports.html",

        total_threats=total_threats,

        critical_threats=critical_threats,

        high_threats=high_threats,

        total_logs=total_logs,

        total_incidents=total_incidents,

        total_ips=total_ips,

        suspicious_ip_count=suspicious_ip_count,

        blocked_ip_count=blocked_ip_count,

        threats=threats_data,

        incidents=incidents_data,

        ips=monitored_ips

    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(

        debug=True

    )