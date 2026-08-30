import os
import pymysql
import pymysql.cursors
import sqlite3
import datetime
import urllib.parse

# Konfigurasi Koneksi MySQL (Bisa disesuaikan via Environment Variable atau default XAMPP/Laragon)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "db_deteksiphishing")
DB_PORT = int(os.environ.get("DB_PORT", 3306))

def get_server_connection():
    """Koneksi awal ke MySQL Server tanpa memilih database tertentu (untuk auto-create DB)"""
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        charset='utf8mb4',
        autocommit=True
    )

def get_connection():
    """Koneksi ke database MySQL target dengan DictCursor"""
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def init_db():
    """
    Inisialisasi Database MySQL:
    1. Membuat database `db_deteksiphishing` jika belum ada.
    2. Membuat tabel `tbl_blacklist`, `tbl_riwayat`, dan `tbl_auto_learning_log`.
    3. Migrasi otomatis data dari SQLite (database.db) jika tersedia dan tabel masih kosong.
    """
    # 1. Pastikan database ada di MySQL
    server_conn = get_server_connection()
    with server_conn.cursor() as s_cursor:
        s_cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    server_conn.close()

    # 2. Inisialisasi tabel di database
    conn = get_connection()
    with conn.cursor() as cursor:
        # Tabel Blacklist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS `tbl_blacklist` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `url` VARCHAR(500) NOT NULL UNIQUE,
            `domain` VARCHAR(255),
            `reason` TEXT,
            `source` VARCHAR(50) DEFAULT 'manual',
            `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # Tabel Riwayat Pengecekan
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS `tbl_riwayat` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `url` TEXT NOT NULL,
            `status` VARCHAR(50) NOT NULL,
            `probability` DOUBLE NOT NULL,
            `source_detection` VARCHAR(100) NOT NULL,
            `scan_time` DATETIME DEFAULT CURRENT_TIMESTAMP,
            `features_json` LONGTEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # Tabel Log Auto-Learning (Simulasi Pembelajaran Mandiri Saat Idle)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS `tbl_auto_learning_log` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `event_name` VARCHAR(100) NOT NULL,
            `generated_url` VARCHAR(500) NOT NULL,
            `confidence_score` DOUBLE NOT NULL,
            `action_taken` VARCHAR(100) NOT NULL,
            `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # 3. Migrasi data dari SQLite database.db jika ada dan MySQL masih kosong
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_blacklist`;")
        res_blacklist = cursor.fetchone()
        
        if res_blacklist['cnt'] == 0:
            migrated = False
            if os.path.exists("database.db"):
                try:
                    sq_conn = sqlite3.connect("database.db")
                    sq_conn.row_factory = sqlite3.Row
                    sq_cur = sq_conn.cursor()

                    # Migrasi Blacklist
                    sq_cur.execute("SELECT url, domain, reason, source, created_at FROM tbl_blacklist;")
                    bl_rows = sq_cur.fetchall()
                    for r in bl_rows:
                        cursor.execute("""
                        INSERT IGNORE INTO `tbl_blacklist` (`url`, `domain`, `reason`, `source`, `created_at`)
                        VALUES (%s, %s, %s, %s, %s);
                        """, (r['url'], r['domain'], r['reason'], r['source'], r['created_at']))

                    # Migrasi Riwayat
                    sq_cur.execute("SELECT url, status, probability, source_detection, scan_time, features_json FROM tbl_riwayat;")
                    rw_rows = sq_cur.fetchall()
                    for r in rw_rows:
                        cursor.execute("""
                        INSERT INTO `tbl_riwayat` (`url`, `status`, `probability`, `source_detection`, `scan_time`, `features_json`)
                        VALUES (%s, %s, %s, %s, %s, %s);
                        """, (r['url'], r['status'], r['probability'], r['source_detection'], r['scan_time'], r['features_json']))

                    # Migrasi Auto-learning Log
                    sq_cur.execute("SELECT event_name, generated_url, confidence_score, action_taken, created_at FROM tbl_auto_learning_log;")
                    al_rows = sq_cur.fetchall()
                    for r in al_rows:
                        cursor.execute("""
                        INSERT INTO `tbl_auto_learning_log` (`event_name`, `generated_url`, `confidence_score`, `action_taken`, `created_at`)
                        VALUES (%s, %s, %s, %s, %s);
                        """, (r['event_name'], r['generated_url'], r['confidence_score'], r['action_taken'], r['created_at']))

                    sq_conn.close()
                    migrated = True
                    print("[INFO] Berhasil migrasi data dari SQLite (database.db) ke MySQL!")
                except Exception as e:
                    print("[INFO] Catatan migrasi SQLite -> MySQL:", e)

            # Jika belum ada data dari SQLite, masukkan seed awal
            if not migrated:
                initial_blacklists = [
                    ("http://phishing-bank-fake-login.com", "phishing-bank-fake-login.com", "Tercatat sebagai phishing aktif oleh Kominfo", "manual"),
                    ("http://update-paypal-security-auth.net/login.php", "update-paypal-security-auth.net", "Pencurian kredensial pengguna", "manual"),
                    ("http://verify-bca-mobile-user.xyz", "verify-bca-mobile-user.xyz", "Pemalsuan tautan perbankan", "manual"),
                    ("http://free-crypto-giveaway-claim.top", "free-crypto-giveaway-claim.top", "Penipuan aset kripto", "manual")
                ]
                for item in initial_blacklists:
                    cursor.execute("""
                    INSERT IGNORE INTO `tbl_blacklist` (`url`, `domain`, `reason`, `source`) 
                    VALUES (%s, %s, %s, %s);
                    """, item)
                print("[INFO] Seed data blacklist awal berhasil dimasukkan ke MySQL!")

    conn.close()

def check_blacklist(url_str):
    """Cek apakah URL atau Domain terdaftar di tabel blacklist MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        url_clean = url_str.strip().rstrip('/')
        parsed = urllib.parse.urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
        domain = (parsed.netloc or parsed.path.split('/')[0]).split(':')[0].strip().lower()
        
        if not domain or domain in ('http', 'https'):
            conn.close()
            return None
            
        cursor.execute("""
        SELECT * FROM `tbl_blacklist` 
        WHERE LOWER(`url`) = %s OR LOWER(`url`) = %s OR LOWER(`domain`) = %s
        LIMIT 1;
        """, (url_str.lower(), url_clean.lower(), domain))
        row = cursor.fetchone()
        
    conn.close()
    return row

def add_to_blacklist(url_str, reason="Terdeteksi Zero-Day Phishing oleh GA+RF", source="zero_day"):
    """Menambahkan URL ke blacklist MySQL"""
    conn = get_connection()
    url_clean = url_str.strip()
    parsed = urllib.parse.urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
    domain = (parsed.netloc or parsed.path.split('/')[0]).split(':')[0].strip()
    
    success = False
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
            INSERT IGNORE INTO `tbl_blacklist` (`url`, `domain`, `reason`, `source`, `created_at`)
            VALUES (%s, %s, %s, %s, %s);
            """, (url_clean, domain, reason, source, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            success = True
    except Exception as e:
        print("Error add_to_blacklist MySQL:", e)
        success = False
        
    conn.close()
    return success

def record_history(url_str, status, probability, source_detection, features_json="{}"):
    """Mencatat histori pemindaian URL ke MySQL"""
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO `tbl_riwayat` (`url`, `status`, `probability`, `source_detection`, `scan_time`, `features_json`)
            VALUES (%s, %s, %s, %s, %s, %s);
            """, (url_str, status, probability, source_detection, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), features_json))
    except Exception as e:
        print("Error record_history MySQL:", e)
    finally:
        conn.close()

def get_history(limit=50):
    """Mengambil riwayat scan terbaru dari MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM `tbl_riwayat` ORDER BY `scan_time` DESC LIMIT %s;", (limit,))
        rows = cursor.fetchall()
    conn.close()
    return rows

def get_blacklists(limit=100):
    """Mengambil daftar blacklist dari MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM `tbl_blacklist` ORDER BY `created_at` DESC LIMIT %s;", (limit,))
        rows = cursor.fetchall()
    conn.close()
    return rows

def delete_blacklist_entry(entry_id):
    """Menghapus entri blacklist berdasarkan ID di MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM `tbl_blacklist` WHERE `id` = %s;", (entry_id,))
    conn.close()

def delete_history_entry(entry_id):
    """Menghapus riwayat scan berdasarkan ID di MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM `tbl_riwayat` WHERE `id` = %s;", (entry_id,))
    conn.close()

def get_dashboard_stats():
    """Mengambil data agregat statistik untuk monitoring dashboard dari MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_riwayat`;")
        total_scans = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_riwayat` WHERE `status` = 'Phishing';")
        phishing_count = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_riwayat` WHERE `status` = 'Aman';")
        legitimate_count = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_blacklist`;")
        blacklist_count = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_blacklist` WHERE `source` = 'zero_day';")
        zero_day_count = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) AS cnt FROM `tbl_auto_learning_log`;")
        auto_learning_count = cursor.fetchone()['cnt']
        
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
    """Mencatat log hasil auto-learning ke MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
        INSERT INTO `tbl_auto_learning_log` (`event_name`, `generated_url`, `confidence_score`, `action_taken`, `created_at`)
        VALUES (%s, %s, %s, %s, %s);
        """, (event_name, generated_url, confidence_score, action_taken, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.close()

def get_auto_learning_logs(limit=20):
    """Mengambil log auto-learning terbaru dari MySQL"""
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM `tbl_auto_learning_log` ORDER BY `created_at` DESC LIMIT %s;", (limit,))
        rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    print("Inisialisasi Database MySQL db_deteksiphishing Selesai!")
    stats = get_dashboard_stats()
    print("Statistik MySQL saat ini:", stats)
