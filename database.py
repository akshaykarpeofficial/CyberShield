import sqlite3


DATABASE = "cybershield.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

def create_database():

    connection = get_connection()

    cursor = connection.cursor()


    # =====================================================
    # THREATS TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            threat_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            description TEXT NOT NULL,

            detected_at TEXT NOT NULL

        )
    """)


    # =====================================================
    # LOGS TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_type TEXT NOT NULL,

            ip_address TEXT NOT NULL,

            status TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
    """)


    # =====================================================
    # INCIDENTS TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            description TEXT NOT NULL,

            status TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
    """)


    # =====================================================
    # IP MONITORING TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitored_ips (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ip_address TEXT UNIQUE NOT NULL,

            status TEXT NOT NULL,

            threat_level TEXT NOT NULL,

            last_seen TEXT NOT NULL

        )
    """)


    connection.commit()

    connection.close()


# =========================================================
# ADD THREAT
# =========================================================

def add_threat(
    threat_type,
    severity,
    description,
    detected_at
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO threats
        (
            threat_type,
            severity,
            description,
            detected_at
        )

        VALUES (?, ?, ?, ?)
    """, (

        threat_type,
        severity,
        description,
        detected_at

    ))


    connection.commit()

    connection.close()


# =========================================================
# GET THREATS
# =========================================================

def get_threats():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM threats
        ORDER BY id DESC
    """)


    threats = cursor.fetchall()

    connection.close()

    return threats


# =========================================================
# ADD LOG
# =========================================================

def add_log(
    event_type,
    ip_address,
    status,
    created_at
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO logs
        (
            event_type,
            ip_address,
            status,
            created_at
        )

        VALUES (?, ?, ?, ?)
    """, (

        event_type,
        ip_address,
        status,
        created_at

    ))


    connection.commit()

    connection.close()


# =========================================================
# GET LOGS
# =========================================================

def get_logs():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM logs
        ORDER BY id DESC
    """)


    logs = cursor.fetchall()

    connection.close()

    return logs


# =========================================================
# ADD INCIDENT
# =========================================================

def add_incident(
    incident_type,
    severity,
    description,
    status,
    created_at
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO incidents
        (
            incident_type,
            severity,
            description,
            status,
            created_at
        )

        VALUES (?, ?, ?, ?, ?)
    """, (

        incident_type,
        severity,
        description,
        status,
        created_at

    ))


    connection.commit()

    connection.close()


# =========================================================
# GET INCIDENTS
# =========================================================

def get_incidents():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
    """)


    incidents = cursor.fetchall()

    connection.close()

    return incidents


# =========================================================
# UPDATE INCIDENT STATUS
# =========================================================

def update_incident_status(
    incident_id,
    status
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        UPDATE incidents

        SET status = ?

        WHERE id = ?
    """, (

        status,
        incident_id

    ))


    connection.commit()

    connection.close()


# =========================================================
# IP MONITORING
# =========================================================

def monitor_ip(
    ip_address,
    status,
    threat_level,
    last_seen
):

    connection = get_connection()

    cursor = connection.cursor()


    # -----------------------------------------------------
    # CHECK WHETHER IP ALREADY EXISTS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT id
        FROM monitored_ips
        WHERE ip_address = ?
    """, (ip_address,))


    existing_ip = cursor.fetchone()


    # -----------------------------------------------------
    # UPDATE EXISTING IP
    # -----------------------------------------------------

    if existing_ip:

        cursor.execute("""
            UPDATE monitored_ips

            SET
                status = ?,
                threat_level = ?,
                last_seen = ?

            WHERE ip_address = ?
        """, (

            status,
            threat_level,
            last_seen,
            ip_address

        ))


    # -----------------------------------------------------
    # ADD NEW IP
    # -----------------------------------------------------

    else:

        cursor.execute("""
            INSERT INTO monitored_ips
            (
                ip_address,
                status,
                threat_level,
                last_seen
            )

            VALUES (?, ?, ?, ?)
        """, (

            ip_address,
            status,
            threat_level,
            last_seen

        ))


    connection.commit()

    connection.close()


# =========================================================
# GET ALL MONITORED IPS
# =========================================================

def get_monitored_ips():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM monitored_ips
        ORDER BY id DESC
    """)


    ips = cursor.fetchall()

    connection.close()

    return ips


# =========================================================
# GET SUSPICIOUS IPS
# =========================================================

def get_suspicious_ips():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM monitored_ips
        WHERE status = 'Suspicious'
        ORDER BY id DESC
    """)


    suspicious_ips = cursor.fetchall()

    connection.close()

    return suspicious_ips


# =========================================================
# GET BLOCKED IPS
# =========================================================

def get_blocked_ips():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM monitored_ips
        WHERE status = 'Blocked'
        ORDER BY id DESC
    """)


    blocked_ips = cursor.fetchall()

    connection.close()

    return blocked_ips


# =========================================================
# GET ALLOWED IPS
# =========================================================

def get_allowed_ips():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM monitored_ips
        WHERE status = 'Allowed'
        ORDER BY id DESC
    """)


    allowed_ips = cursor.fetchall()

    connection.close()

    return allowed_ips


# =========================================================
# RUN DATABASE CREATION
# =========================================================

if __name__ == "__main__":

    create_database()

    print("CyberShield database initialized successfully.")