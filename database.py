import sqlite3
import datetime
import urllib.parse

DB_PATH = "database.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Tabel Blacklist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tbl_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        domain TEXT,
        reason TEXT,
        source TEXT DEFAULT 'manual',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Tabel Riwayat Pengecekan
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tbl_riwayat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        status TEXT NOT NULL,
        probability REAL NOT NULL,
        source_detection TEXT NOT NULL,
        scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        features_json TEXT
    );
    """)
    
    # 3. Tabel Log Auto-Learning (Simulasi Pembelajaran Mandiri Saat Idle)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tbl_auto_learning_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_name TEXT NOT NULL,
        generated_url TEXT NOT NULL,
        confidence_score REAL NOT NULL,
        action_taken TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Seed data blacklist awal jika masih kosong
    cursor.execute("SELECT COUNT(*) FROM tbl_blacklist;")
    if cursor.fetchone()[0] == 0:
        initial_blacklists = [
            ("http://phishing-bank-fake-login.com", "phishing-bank-fake-login.com", "Tercatat sebagai phishing aktif oleh Kominfo", "manual"),
            ("http://update-paypal-security-auth.net/login.php", "update-paypal-security-auth.net", "Pencurian kredensial pengguna", "manual"),
            ("http://verify-bca-mobile-user.xyz", "verify-bca-mobile-user.xyz", "Pemalsuan tautan perbankan", "manual"),
            ("http://free-crypto-giveaway-claim.top", "free-crypto-giveaway-claim.top", "Penipuan aset kripto", "manual")
        ]
        cursor.executemany("""
        INSERT INTO tbl_blacklist (url, domain, reason, source) VALUES (?, ?, ?, ?);
        """, initial_blacklists)
        
    conn.commit()
    conn.close()

def check_blacklist(url_str):
    conn = get_connection()
    cursor = conn.cursor()
    
    url_clean = url_str.strip().rstrip('/')
    parsed = urllib.parse.urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
    domain = (parsed.netloc or parsed.path.split('/')[0]).split(':')[0].strip().lower()
    
    if not domain or domain == 'http' or domain == 'https':
        conn.close()
        return None
        
    # Pencocokan persis URL atau domain yang valid
    cursor.execute("""
    SELECT * FROM tbl_blacklist 
    WHERE LOWER(url) = ? OR LOWER(url) = ? OR LOWER(domain) = ?;
    """, (url_str.lower(), url_clean.lower(), domain))
    
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_to_blacklist(url_str, reason="Terdeteksi Zero-Day Phishing oleh GA+RF", source="zero_day"):
    conn = get_connection()
    cursor = conn.cursor()
    
    url_clean = url_str.strip()
    parsed = urllib.parse.urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
    domain = (parsed.netloc or parsed.path.split('/')[0]).split(':')[0].strip()
    
    try:
        cursor.execute("""
        INSERT OR IGNORE INTO tbl_blacklist (url, domain, reason, source, created_at)
        VALUES (?, ?, ?, ?, ?);
        """, (url_clean, domain, reason, source, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        success = True
    except Exception as e:
        print("Error add_to_blacklist:", e)
        success = False
        
    conn.close()
    return success

def record_history(url_str, status, probability, source_detection, features_json="{}"):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO tbl_riwayat (url, status, probability, source_detection, scan_time, features_json)
    VALUES (?, ?, ?, ?, ?, ?);
    """, (url_str, status, probability, source_detection, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), features_json))
    
    conn.commit()
    conn.close()

def get_history(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tbl_riwayat ORDER BY scan_time DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_blacklists(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tbl_blacklist ORDER BY created_at DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def delete_blacklist_entry(entry_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tbl_blacklist WHERE id = ?;", (entry_id,))
    conn.commit()
    conn.close()

def delete_history_entry(entry_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tbl_riwayat WHERE id = ?;", (entry_id,))
    conn.commit()
    conn.close()

def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM tbl_riwayat;")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tbl_riwayat WHERE status = 'Phishing';")
    phishing_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tbl_riwayat WHERE status = 'Aman';")
    legitimate_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tbl_blacklist;")
    blacklist_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tbl_blacklist WHERE source = 'zero_day';")
    zero_day_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tbl_auto_learning_log;")
    auto_learning_count = cursor.fetchone()[0]
    
    conn.close()
    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "legitimate_count": legitimate_count,
        "blacklist_count": blacklist_count,
        "zero_day_count": zero_day_count,
        "auto_learning_count": auto_learning_count
    }

def record_auto_learning_log(event_name, generated_url, confidence_score, action_taken):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO tbl_auto_learning_log (event_name, generated_url, confidence_score, action_taken, created_at)
    VALUES (?, ?, ?, ?, ?);
    """, (event_name, generated_url, confidence_score, action_taken, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_auto_learning_logs(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tbl_auto_learning_log ORDER BY created_at DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    init_db()
    print("Database manager updated.")
