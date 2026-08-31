/**
 * PhishGuard - Frontend Application Script
 * Powered by Vue.js 3
 * Hybrid GA (Genetic Algorithm) + Random Forest Classifier (MySQL Edition)
 */

const { createApp } = Vue;

const app = createApp({
    delimiters: ['[[', ']]'],
    data() {
        return {
            activeTab: 'scanner',
            scanUrlInput: '',
            isScanning: false,
            scanStep: 1,
            scanStepText: 'Memeriksa Database Blacklist...',
            scanResult: null,
            showFeatureModal: true, // Default terbuka agar langsung terlihat
            featureFilter: 'all', // 'all', 'risk', 'safe'
            selectedFeatureKey: null,
            selectedFeatureValue: null,
            selectedHistoryLog: null,
            dictSearch: '',
            selectedDictCategory: 'Semua',
            stats: {},
            blacklists: [],
            historyLogs: [],
            autoLearningLogs: [],
            isAutoLearning: false,

            // Kamus & Ensiklopedia 20 Fitur Leksikal Genetic Algorithm
            lexicalDictionary: {
                "URLLength": {
                    "name": "Panjang Total URL",
                    "category": "Struktur URL",
                    "description": "Menghitung jumlah total karakter pada string URL. URL phishing cenderung memiliki panjang lebih dari 54 karakter untuk menyembunyikan token atau subdomain palsu.",
                    "safe_criteria": "<= 54 karakter",
                    "risk_criteria": "> 54 karakter"
                },
                "IsDomainIP": {
                    "name": "Format Alamat IP",
                    "category": "Domain & Host",
                    "description": "Mendeteksi apakah host URL menggunakan alamat IP numerik mentah (misal: 192.168.1.1) tanpa nama domain resmi terdaftar (FQDN).",
                    "safe_criteria": "0 (Domain FQDN Sah)",
                    "risk_criteria": "1 (Alamat IP Mentah)"
                },
                "CharContinuationRate": {
                    "name": "Tingkat Kontinuitas Karakter",
                    "category": "Leksikal & Pola",
                    "description": "Rasio kesinambungan karakter leksikal URL. Nilai rendah mengindikasikan struktur nama domain/path yang terdistorsi atau teracak secara artifisial.",
                    "safe_criteria": ">= 0.85 (Stabil)",
                    "risk_criteria": "< 0.85 (Terdistorsi / Acak)"
                },
                "TLDLength": {
                    "name": "Panjang Karakter TLD",
                    "category": "Domain & Host",
                    "description": "Jumlah karakter pada ekstensi domain (contoh: .com = 3, .online = 6). TLD yang panjang atau tidak lazim sering dipakai penyedia domain gratis penipuan.",
                    "safe_criteria": "2 - 4 karakter (.com, .id, .org)",
                    "risk_criteria": ">= 5 karakter atau TLD berisiko"
                },
                "NoOfSubDomain": {
                    "name": "Jumlah Subdomain",
                    "category": "Domain & Host",
                    "description": "Banyaknya tingkatan subdomain pada URL. Penyerang sering menyisipkan subdomain berantai (contoh: bca.klik.login.domain-palsu.com) untuk meniru brand asli.",
                    "safe_criteria": "<= 1 subdomain (atau www)",
                    "risk_criteria": ">= 2 subdomain berantai"
                },
                "HasObfuscation": {
                    "name": "Deteksi Obfuscation / Penyamaran",
                    "category": "Penyamaran & Encoding",
                    "description": "Mendeteksi keberadaan pola manipulasi URL seperti % hex encoding, karakter @ untuk redirect, atau double slash '//' di luar protokol.",
                    "safe_criteria": "0 (URL Bersih / Polos)",
                    "risk_criteria": "1 (Terdapat Pola Penyamaran)"
                },
                "ObfuscationRatio": {
                    "name": "Rasio Karakter Obfuscation",
                    "category": "Penyamaran & Encoding",
                    "description": "Persentase proporsi karakter penyamar / hex encoding terhadap total panjang URL.",
                    "safe_criteria": "<= 0.02 (Wajar)",
                    "risk_criteria": "> 0.02 (Banyak Simbol Hex/Obf)"
                },
                "NoOfDegitsInURL": {
                    "name": "Jumlah Karakter Angka",
                    "category": "Struktur URL",
                    "description": "Banyaknya karakter angka numerik (0-9) di dalam string URL. URL phishing sering memuat ID sesi buatan atau nomor acak panjang.",
                    "safe_criteria": "<= 3 angka",
                    "risk_criteria": "> 3 angka"
                },
                "NoOfQMarkInURL": {
                    "name": "Jumlah Tanda Tanya (?)",
                    "category": "Query & Parameter",
                    "description": "Jumlah tanda tanya pemisah query parameter pada URL. Sering dimanipulasi pada serangan skimming formulir login palsu.",
                    "safe_criteria": "<= 1 tanda tanya",
                    "risk_criteria": "> 1 tanda tanya"
                },
                "SpacialCharRatioInURL": {
                    "name": "Rasio Simbol Khusus",
                    "category": "Leksikal & Pola",
                    "description": "Proporsi simbol khusus (@, -, _, =, ?, &, %, ., ~, +, #, :, ;) terhadap total karakter URL.",
                    "safe_criteria": "<= 0.12 (Standar)",
                    "risk_criteria": "> 0.12 (Banyak Simbol Khusus)"
                },
                "IsHTTPS": {
                    "name": "Protokol Keamanan HTTPS",
                    "category": "Protokol & Keamanan",
                    "description": "Memeriksa apakah URL menggunakan enkripsi TLS/SSL (HTTPS) atau HTTP biasa yang tidak terenkripsi.",
                    "safe_criteria": "1 (HTTPS Aktif)",
                    "risk_criteria": "0 (HTTP Biasa / Tidak Aman)"
                },
                "HasTitle": {
                    "name": "Struktur Judul Leksikal",
                    "category": "Semantik Leksikal",
                    "description": "Indikator keteraturan sintaks penamaan dan judul domain sesuai hierarki web sah.",
                    "safe_criteria": "1 (Memiliki Struktur Sah)",
                    "risk_criteria": "0 (Terdistorsi / Rusak)"
                },
                "IsResponsive": {
                    "name": "Format Responsif Leksikal",
                    "category": "Semantik Leksikal",
                    "description": "Karakteristik path URL yang mencerminkan standar arsitektur web aplikasi modern yang responsif.",
                    "safe_criteria": "1 (Format Modern)",
                    "risk_criteria": "0 (Format Kuno / Meragukan)"
                },
                "NoOfPopup": {
                    "name": "Indikator Popup Leksikal",
                    "category": "Semantik Leksikal",
                    "description": "Deteksi parameter penanganan dialog modal atau pop-up instan yang sering memicu phishing alert palsu.",
                    "safe_criteria": "0 (Tanpa Trigger Popup)",
                    "risk_criteria": "> 0 (Terdapat Trigger Popup)"
                },
                "HasExternalFormSubmit": {
                    "name": "Form Action Eksternal",
                    "category": "Interaksi & Form",
                    "description": "Mendeteksi parameter formulir yang mengarahkan pengiriman data (POST action) ke host pihak ketiga yang berbeda.",
                    "safe_criteria": "0 (Internal Host)",
                    "risk_criteria": "1 (Mengarahkan ke Eksternal)"
                },
                "HasSubmitButton": {
                    "name": "Elemen Submit Interaktif",
                    "category": "Interaksi & Form",
                    "description": "Ketersediaan parameter aksi pengiriman data form yang sah.",
                    "safe_criteria": "1 (Elemen Lengkap)",
                    "risk_criteria": "0 (Fake Clone Frame)"
                },
                "HasHiddenFields": {
                    "name": "Input Field Tersembunyi",
                    "category": "Interaksi & Form",
                    "description": "Indikator field tersembunyi (hidden input) yang kerap dipakai skimming credential atau stealing token rahasia.",
                    "safe_criteria": "0 (Transparan)",
                    "risk_criteria": "1 (Field Tersembunyi)"
                },
                "Pay": {
                    "name": "Kata Kunci Finansial / Payment",
                    "category": "Finansial & Brand",
                    "description": "Mendeteksi kata kunci pembayaran/keuangan (pay, billing, card, payment, wallet, crypto). Domain tidak resmi dengan keyword ini sangat berisiko.",
                    "safe_criteria": "0 (Non-Finansial) atau Domain Resmi",
                    "risk_criteria": "1 pada domain tidak resmi"
                },
                "HasCopyrightInfo": {
                    "name": "Integritas Hak Cipta Domain",
                    "category": "Semantik Leksikal",
                    "description": "Indikator legitimasi kepemilikan merek dan domain resmi vs domain clone penipu.",
                    "safe_criteria": "1 (Domain Sah / Terpercaya)",
                    "risk_criteria": "0 (Domain Tidak Dikenal)"
                },
                "NoOfEmptyRef": {
                    "name": "Referensi Tautan Kosong (#)",
                    "category": "Semantik Leksikal",
                    "description": "Banyaknya tautan kosong '#' pada halaman. Template phishing sering menyisakan banyak tombol mati / empty ref.",
                    "safe_criteria": ">= 1 (Struktur Utuh)",
                    "risk_criteria": "0 pada situs penipuan statis"
                }
            }
        };
    },
    computed: {
        dictionaryCategories() {
            const cats = new Set(['Semua']);
            for (const key in this.lexicalDictionary) {
                cats.add(this.lexicalDictionary[key].category);
            }
            return Array.from(cats);
        },
        filteredDictionary() {
            const result = {};
            const q = this.dictSearch.trim().toLowerCase();
            const cat = this.selectedDictCategory;

            for (const key in this.lexicalDictionary) {
                const item = this.lexicalDictionary[key];
                const matchCat = (cat === 'Semua' || item.category === cat);
                const matchQuery = !q || key.toLowerCase().includes(q) || item.name.toLowerCase().includes(q) || item.description.toLowerCase().includes(q);
                if (matchCat && matchQuery) {
                    result[key] = item;
                }
            }
            return result;
        },
        filteredFeatures() {
            if (!this.scanResult || !this.scanResult.features) return {};
            const features = this.scanResult.features;
            if (this.featureFilter === 'all') return features;

            const filtered = {};
            for (const key in features) {
                const assessment = this.getFeatureAssessment(key, features[key]);
                if (this.featureFilter === 'risk' && assessment.status === 'risk') {
                    filtered[key] = features[key];
                } else if (this.featureFilter === 'safe' && assessment.status === 'safe') {
                    filtered[key] = features[key];
                }
            }
            return filtered;
        }
    },
    mounted() {
        this.fetchStats();
        this.fetchBlacklists();
        this.fetchHistory();
    },
    methods: {
        fillSample(url) {
            this.scanUrlInput = url;
        },
        async pasteFromClipboard() {
            try {
                const text = await navigator.clipboard.readText();
                if (text) this.scanUrlInput = text.trim();
            } catch (e) {
                alert("Tidak dapat mengakses clipboard secara otomatis. Silakan paste manual.");
            }
        },
        getFeatureIndex(key) {
            const keys = Object.keys(this.lexicalDictionary);
            return keys.indexOf(key) + 1;
        },
        getFeatureName(key) {
            return this.lexicalDictionary[key] ? this.lexicalDictionary[key].name : key;
        },
        getFeatureCategory(key) {
            return this.lexicalDictionary[key] ? this.lexicalDictionary[key].category : 'Leksikal';
        },
        getFeatureDescription(key) {
            return this.lexicalDictionary[key] ? this.lexicalDictionary[key].description : '-';
        },
        getFeatureSafeCriteria(key) {
            return this.lexicalDictionary[key] ? this.lexicalDictionary[key].safe_criteria : '-';
        },
        getFeatureRiskCriteria(key) {
            return this.lexicalDictionary[key] ? this.lexicalDictionary[key].risk_criteria : '-';
        },
        getFeatureAssessment(key, val) {
            const v = parseFloat(val) || 0;
            if (key === 'URLLength') return v <= 54 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Panjang (>54)' };
            if (key === 'IsDomainIP') return v === 0 ? { status: 'safe', label: 'Domain Sah' } : { status: 'risk', label: 'Alamat IP' };
            if (key === 'CharContinuationRate') return v >= 0.85 ? { status: 'safe', label: 'Stabil' } : { status: 'risk', label: 'Terdistorsi' };
            if (key === 'TLDLength') return v <= 4 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'TLD Berisiko' };
            if (key === 'NoOfSubDomain') return v <= 1 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Multi-Subdomain' };
            if (key === 'HasObfuscation') return v === 0 ? { status: 'safe', label: 'Bersih' } : { status: 'risk', label: 'Ada Obfuscation' };
            if (key === 'ObfuscationRatio') return v <= 0.02 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Rasio Tinggi' };
            if (key === 'NoOfDegitsInURL') return v <= 3 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Banyak Angka' };
            if (key === 'NoOfQMarkInURL') return v <= 1 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Banyak Query' };
            if (key === 'SpacialCharRatioInURL') return v <= 0.12 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Banyak Simbol' };
            if (key === 'IsHTTPS') return v === 1 ? { status: 'safe', label: 'HTTPS Aktif' } : { status: 'risk', label: 'HTTP Biasa' };
            if (key === 'HasTitle') return v === 1 ? { status: 'safe', label: 'Sah' } : { status: 'risk', label: 'Terdistorsi' };
            if (key === 'IsResponsive') return v === 1 ? { status: 'safe', label: 'Modern' } : { status: 'risk', label: 'Kuno' };
            if (key === 'NoOfPopup') return v === 0 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Ada Popup' };
            if (key === 'HasExternalFormSubmit') return v === 0 ? { status: 'safe', label: 'Internal' } : { status: 'risk', label: 'Form Eksternal' };
            if (key === 'HasSubmitButton') return v === 1 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Fake Frame' };
            if (key === 'HasHiddenFields') return v === 0 ? { status: 'safe', label: 'Transparan' } : { status: 'risk', label: 'Ada Hidden Field' };
            if (key === 'Pay') return v === 0 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Kata Finansial' };
            if (key === 'HasCopyrightInfo') return v === 1 ? { status: 'safe', label: 'Sah' } : { status: 'risk', label: 'Tidak Dikenal' };
            if (key === 'NoOfEmptyRef') return v >= 1 ? { status: 'safe', label: 'Normal' } : { status: 'risk', label: 'Empty Ref' };
            return { status: 'safe', label: 'Normal' };
        },
        getFeatureCount(type) {
            if (!this.scanResult || !this.scanResult.features) return 0;
            let count = 0;
            for (const key in this.scanResult.features) {
                const assessment = this.getFeatureAssessment(key, this.scanResult.features[key]);
                if (assessment.status === type) count++;
            }
            return count;
        },
        openFeatureDetailModal(key, val) {
            this.selectedFeatureKey = key;
            this.selectedFeatureValue = val;
        },
        openHistoryFeaturesModal(log) {
            this.selectedHistoryLog = log;
        },
        async runScan() {
            if (!this.scanUrlInput.trim()) return;

            this.isScanning = true;
            this.scanResult = null;
            this.scanStep = 1;
            this.scanStepText = 'Memeriksa Database Blacklist MySQL (tbl_blacklist)...';

            await new Promise(r => setTimeout(r, 250));
            this.scanStep = 2;
            this.scanStepText = 'Ekstraksi 20 Fitur Leksikal Genetic Algorithm...';

            await new Promise(r => setTimeout(r, 250));
            this.scanStep = 3;
            this.scanStepText = 'Klasifikasi Prediksi Model Random Forest...';

            await new Promise(r => setTimeout(r, 200));
            this.scanStep = 4;
            this.scanStepText = 'Evaluasi Pertahanan Zero-Day Security...';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: this.scanUrlInput })
                });
                const data = await res.json();
                if (res.ok) {
                    this.scanResult = data;
                    this.showFeatureModal = true;
                    this.fetchStats();
                    this.fetchBlacklists();
                    this.fetchHistory();
                } else {
                    alert(data.message || "Terjadi kesalahan saat memindai URL.");
                }
            } catch (e) {
                console.error(e);
                alert("Gagal terhubung ke server backend MySQL.");
            } finally {
                this.isScanning = false;
            }
        },
        async fetchStats() {
            try {
                const res = await fetch('/api/stats');
                this.stats = await res.json();
            } catch (e) {
                console.error(e);
            }
        },
        async fetchBlacklists() {
            try {
                const res = await fetch('/api/blacklist');
                this.blacklists = await res.json();
            } catch (e) {
                console.error(e);
            }
        },
        async fetchHistory() {
            try {
                const res = await fetch('/api/riwayat');
                this.historyLogs = await res.json();
            } catch (e) {
                console.error(e);
            }
        },
        async triggerAutoLearning() {
            this.isAutoLearning = true;
            try {
                const res = await fetch('/api/auto-learning', { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    this.autoLearningLogs = data.patterns;
                    this.fetchBlacklists();
                    this.fetchStats();
                }
            } catch (e) {
                console.error(e);
            } finally {
                this.isAutoLearning = false;
            }
        }
    }
});

app.mount('#app');
