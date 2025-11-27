import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

def get_db_connection():
    """Get SQLite connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database (run once)"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create table if not exists
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_name TEXT NOT NULL,
        image_digest TEXT NOT NULL UNIQUE,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        trivy_output_hash TEXT,
        report_path TEXT,
        severity_filter TEXT,
        fail_threshold INTEGER,
        fail_severity TEXT,
        cache_expire_hours INTEGER DEFAULT 24
    )
    """)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")