import sqlite3
from pathlib import Path


DATABASE_PATH = Path("database") / "scanner.db"


def get_connection():
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    return connection


# ---------------------------------------------------------
# Database Creation / Migration
# ---------------------------------------------------------

def create_database():

    connection = get_connection()
    cursor = connection.cursor()

    # -----------------------------------------------------
    # Users
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # Scans
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'tcp',
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # -----------------------------------------------------
    # Scan Results
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host TEXT,
            protocol TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # -----------------------------------------------------
    # Migration: scans.scan_type
    # -----------------------------------------------------

    cursor.execute("""
        PRAGMA table_info(scans)
    """)

    scan_columns = [
        row[1]
        for row in cursor.fetchall()
    ]

    if "scan_type" not in scan_columns:

        cursor.execute("""
            ALTER TABLE scans
            ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'tcp'
        """)

    # -----------------------------------------------------
    # Migration: scans.user_id
    # -----------------------------------------------------

    if "user_id" not in scan_columns:

        cursor.execute("""
            ALTER TABLE scans
            ADD COLUMN user_id INTEGER
        """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# User Functions
# ---------------------------------------------------------

def create_user(
    user_name,       # stored as full_name internally
    username,       # actual username
    email,
    password_hash,
    created_at
):

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users (
                full_name,
                username,
                email,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_name,
                username,
                email,
                password_hash,
                created_at
            )
        )

        connection.commit()

        user_id = cursor.lastrowid

        connection.close()

        return user_id

    except sqlite3.IntegrityError:

        connection.close()

        return None


def get_user_by_email(email):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            username,
            email,
            password_hash,
            created_at
        FROM users
        WHERE LOWER(email) = LOWER(?)
        """,
        (email,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


def get_user_by_username(username):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            username,
            email,
            password_hash,
            created_at
        FROM users
        WHERE LOWER(username) = LOWER(?)
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


def get_user_by_id(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            username,
            email,
            password_hash,
            created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


# ---------------------------------------------------------
# Scan Functions
# ---------------------------------------------------------

def save_scan(
    target,
    scan_date,
    scan_type="tcp",
    user_id=None
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO scans (
            target,
            scan_date,
            scan_type,
            user_id
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            target,
            scan_date,
            scan_type,
            user_id
        )
    )

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return scan_id


def save_scan_results(scan_id, results):

    connection = get_connection()
    cursor = connection.cursor()

    for result in results:

        cursor.execute(
            """
            INSERT INTO scan_results (
                scan_id,
                host,
                protocol,
                port,
                state,
                service,
                product,
                version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.get("host", ""),
                result.get("protocol", ""),
                result.get("port"),
                result.get("state", ""),
                result.get("service", ""),
                result.get("product", ""),
                result.get("version", "")
            )
        )

    connection.commit()
    connection.close()


def get_scans(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            scan_type
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    )

    scans = cursor.fetchall()

    connection.close()

    return scans


def get_scan_by_id(scan_id, user_id=None):

    connection = get_connection()
    cursor = connection.cursor()

    if user_id is None:

        cursor.execute(
            """
            SELECT
                id,
                target,
                scan_date,
                scan_type
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        )

    else:

        cursor.execute(
            """
            SELECT
                id,
                target,
                scan_date,
                scan_type
            FROM scans
            WHERE id = ?
            AND user_id = ?
            """,
            (
                scan_id,
                user_id
            )
        )

    scan = cursor.fetchone()

    connection.close()

    return scan


def get_recent_scans(
    user_id,
    limit=5
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            scan_type
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (
            user_id,
            limit
        )
    )

    scans = cursor.fetchall()

    connection.close()

    return scans


def get_scan_results(scan_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            host,
            protocol,
            port,
            state,
            service,
            product,
            version
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY port
        """,
        (scan_id,)
    )

    rows = cursor.fetchall()

    connection.close()

    results = []

    for row in rows:

        results.append({
            "host": row[0],
            "protocol": row[1],
            "port": row[2],
            "state": row[3],
            "service": row[4],
            "product": row[5],
            "version": row[6]
        })

    return results


# ---------------------------------------------------------
# Dashboard Statistics
# ---------------------------------------------------------

def get_total_scans(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ?
        """,
        (user_id,)
    )

    total_scans = cursor.fetchone()[0]

    connection.close()

    return total_scans


def get_total_open_ports(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scan_results
        INNER JOIN scans
            ON scan_results.scan_id = scans.id
        WHERE scans.user_id = ?
        AND scan_results.state = 'open'
        """,
        (user_id,)
    )

    total_open_ports = cursor.fetchone()[0]

    connection.close()

    return total_open_ports


def get_latest_scan(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            scan_type
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,)
    )

    latest_scan = cursor.fetchone()

    connection.close()

    return latest_scan