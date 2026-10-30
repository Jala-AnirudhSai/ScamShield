import sqlite3
import os

DATABASE_NAME = "scamshield.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            recommendations_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan_result(message, risk_score, risk_level, indicators_json, recommendations_json):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (message, risk_score, risk_level, indicators_json, recommendations_json)
        VALUES (?, ?, ?, ?, ?)
    """, (message, risk_score, risk_level, indicators_json, recommendations_json))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_all_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, message, risk_score, risk_level FROM scan_history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Critical'")
    critical_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'High'")
    high_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Medium'")
    medium_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Low'")
    low_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT id, timestamp, message, risk_score, risk_level FROM scan_history ORDER BY id DESC LIMIT 5")
    recent_scans = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_scans": total_scans,
        "high_risk_scans": critical_scans + high_scans,
        "medium_risk_scans": medium_scans,
        "low_risk_scans": low_scans,
        "recent_scans": recent_scans
    }

def clear_scan_history():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()
