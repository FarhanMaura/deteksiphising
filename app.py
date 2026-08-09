import os
import json
import random
import datetime
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

from extractor import extract_features
from database import (
    init_db, check_blacklist, add_to_blacklist, record_history,
    get_history, get_blacklists, delete_blacklist_entry, delete_history_entry,
    get_dashboard_stats, record_auto_learning_log, get_auto_learning_logs
)

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Inisialisasi Database
init_db()

# Load Model ML dan Fitur Terpilih
MODEL_PATH = "model_rf_phishing.pkl"
FEATURES_PATH = "fitur_terpilih.pkl"

rf_model = None
selected_features = []

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
        rf_model = joblib.load(MODEL_PATH)
        selected_features = joblib.load(FEATURES_PATH)
        print(f"Model Random Forest & {len(selected_features)} fitur terpilih GA berhasil dimuat!")
    else:
        print("PERINGATAN: File model atau fitur_terpilih tidak ditemukan!")
except Exception as e:
    print("Error saat memuat model:", e)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan_url():
    data = request.get_json() or {}
    raw_url = data.get("url", "").strip()
    
    if not raw_url:
        return jsonify({"status": "error", "message": "URL tidak boleh kosong!"}), 400
        
    # Auto-normalize: jika user hanya mengetik 'youtube.com' tanpa protocol,
    # kita asumsikan skema default HTTPS
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        url_input = "https://" + raw_url
    else:
        url_input = raw_url
        
    # ----------------------------------------------------
    # LAPISAN 1: Pengecekan Basis Data Lokal (Blacklist)
    # ----------------------------------------------------
    blacklist_match = check_blacklist(url_input)
    if blacklist_match:
        # Catat ke riwayat
        record_history(
            url_str=url_input,
            status="Phishing",
            probability=100.0,
            source_detection="Blacklist Hit",
            features_json=json.dumps({"info": "URL terdaftar di blacklist lokal"})
        )
        return jsonify({
            "status": "Phishing",
            "is_phishing": True,
            "probability": 100.0,
            "source_detection": "Blacklist Hit",
            "zero_day": False,
            "blacklist_info": blacklist_match,
            "features": {}
        })
        
    # ----------------------------------------------------
    # LAPISAN 2: Ekstraksi Fitur Leksikal (20 Fitur GA) + RF
    # ----------------------------------------------------
    if rf_model is None:
        return jsonify({"status": "error", "message": "Model Machine Learning belum siap!"}), 500
        
    X_arr, feature_dict = extract_features(url_input)
    
    # Prediksi Random Forest
    pred_class = rf_model.predict(X_arr)[0]
    probabilities = rf_model.predict_proba(X_arr)[0]
    
    # Pada Dataset PhiUSIIL: Class 0 = Phishing, Class 1 = Legitimate (Aman)
    if len(probabilities) == 2:
        prob_phishing = float(probabilities[0]) * 100.0  # Index 0 adalah Phishing
    else:
        prob_phishing = 100.0 if str(pred_class) == '0' else 0.0
        
    is_phishing = (int(pred_class) == 0 or prob_phishing > 50.0)
    final_status = "Phishing" if is_phishing else "Aman"
    
    # ----------------------------------------------------
    # LAPISAN 3: Zero-Day Security & Auto-Blacklist Update
    # ----------------------------------------------------
    zero_day_triggered = False
    if is_phishing:
        zero_day_triggered = True
        add_to_blacklist(
            url_str=url_input,
            reason=f"Terdeteksi Zero-Day Phishing oleh Random Forest (Probabilitas {prob_phishing:.1f}%)",
            source="zero_day"
        )
        
    # Catat Rekam Jejak ke tbl_riwayat
    record_history(
        url_str=url_input,
        status=final_status,
        probability=round(prob_phishing if is_phishing else (100.0 - prob_phishing), 2),
        source_detection="GA + Random Forest Model",
        features_json=json.dumps(feature_dict)
    )
    
    return jsonify({
        "status": final_status,
        "is_phishing": is_phishing,
        "probability": round(prob_phishing if is_phishing else (100.0 - prob_phishing), 2),
        "source_detection": "GA + Random Forest Model",
        "zero_day": zero_day_triggered,
        "features": feature_dict
    })

@app.route("/api/stats", methods=["GET"])
def get_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)

@app.route("/api/riwayat", methods=["GET"])
def fetch_history():
    logs = get_history(limit=100)
    return jsonify(logs)

@app.route("/api/riwayat/<int:entry_id>", methods=["DELETE"])
def remove_history(entry_id):
    delete_history_entry(entry_id)
    return jsonify({"status": "success"})

@app.route("/api/blacklist", methods=["GET"])
def fetch_blacklists():
    items = get_blacklists(limit=150)
    return jsonify(items)

@app.route("/api/blacklist", methods=["POST"])
def create_blacklist():
    data = request.get_json() or {}
    url_input = data.get("url", "").strip()
    reason = data.get("reason", "Ditambahkan manual oleh admin").strip()
    
    if not url_input:
        return jsonify({"status": "error", "message": "URL tidak boleh kosong!"}), 400
        
    success = add_to_blacklist(url_input, reason=reason, source="manual")
    if success:
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "message": "Gagal menambahkan URL ke blacklist"}), 500

@app.route("/api/blacklist/<int:entry_id>", methods=["DELETE"])
def remove_blacklist(entry_id):
    delete_blacklist_entry(entry_id)
    return jsonify({"status": "success"})

@app.route("/api/auto-learning", methods=["POST", "GET"])
def run_auto_learning():
    """
    Simulasi Fitur Otomatis Pembelajaran Mandiri (Auto-Learning / Idle Generator):
    Membangkitkan variasi pola link phishing sintetis secara internal (tanpa crawling), 
    menguji ke model GA+RF, dan mendaftarkan pola phishing baru ke basis data blacklist.
    """
    if request.method == "GET":
        logs = get_auto_learning_logs(limit=20)
        return jsonify(logs)
        
    # Generate variasi pola URL phishing baru yang realistis secara sintesis
    domains = ["secure-bank-verification", "paypal-update-account", "bca-mobile-auth-login", "tokopedia-reward-claim", "crypto-wallet-verify"]
    tlds = [".xyz", ".online", ".site", ".top", ".info"]
    paths = ["/login-verify-account.php", "/checkpoint/auth", "/secure/update", "/confirm-user"]
    
    generated_patterns = []
    registered_count = 0
    
    for _ in range(3):
        rnd_domain = random.choice(domains) + "-" + str(random.randint(100, 999))
        rnd_tld = random.choice(tlds)
        rnd_path = random.choice(paths)
        synthetic_url = f"http://192.168.{random.randint(1,250)}.{random.randint(1,250)}{rnd_path}?ref=account_verification_{rnd_domain}%20obf"
        
        X_arr, f_dict = extract_features(synthetic_url)
        probs = rf_model.predict_proba(X_arr)[0]
        prob_phish = float(probs[0]) * 100.0  # Index 0 adalah Phishing
        
        if prob_phish > 50.0:
            add_to_blacklist(
                url_str=synthetic_url,
                reason=f"Pola Phishing Baru Hasil Auto-Learning Mandiri (Probabilitas GA+RF {prob_phish:.1f}%)",
                source="auto_learning"
            )
            record_auto_learning_log(
                event_name="Sintesis Pola URL Zero-Day",
                generated_url=synthetic_url,
                confidence_score=round(prob_phish, 2),
                action_taken="Otomatis Ditambahkan ke tbl_blacklist"
            )
            registered_count += 1
            
        generated_patterns.append({
            "url": synthetic_url,
            "phishing_confidence": round(prob_phish, 2),
            "added_to_blacklist": prob_phish > 50.0
        })
        
    return jsonify({
        "status": "success",
        "message": f"Auto-Learning selesai! {registered_count} pola phishing zero-day berhasil dipelajari dan ditambahkan ke blacklist.",
        "patterns": generated_patterns
    })

if __name__ == "__main__":
    print("Memulai Server Flask Aplikasi Deteksi Phishing...")
    app.run(host="0.0.0.0", port=5000, debug=True)
