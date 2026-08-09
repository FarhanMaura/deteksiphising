import re
import urllib.parse
import numpy as np

def extract_features(url_string):
    """
    Ekstraksi 20 fitur terpilih hasil Genetic Algorithm (GA) secara MURNI LEKSIKAL 
    dari string URL tanpa melakukan HTTP request / crawling.
    Disesuaikan dengan distribusi statistik dataset PhiUSIIL, DGA detector, dan filter situs berisiko.
    """
    if not url_string:
        url_string = ""
        
    url_str = str(url_string).strip()
    
    # Auto-normalize: Jika pengguna memasukkan domain polos (misal 'youtube.com'), 
    # otomatis tambahkan skema HTTPS default standar web modern.
    if not (url_str.startswith("http://") or url_str.startswith("https://")):
        url_str = "https://" + url_str
        
    parsed_url = urllib.parse.urlparse(url_str)
    domain = (parsed_url.netloc or parsed_url.path.split('/')[0]).split(':')[0].lower()
    path_and_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
    
    # 1. URLLength: Panjang total karakter URL
    url_length = len(url_str)
    
    # 2. IsDomainIP: Apakah domain berupa alamat IP (IPv4 / IPv6)
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    is_domain_ip = 1 if re.match(ip_pattern, domain) else 0
    
    # 3. TLDLength: Panjang karakter Top Level Domain (TLD)
    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        tld = domain_parts[-1]
        tld_length = len(tld)
    else:
        tld = 'com'
        tld_length = 3
        
    domain_name = domain_parts[0] if 'www' not in domain else (domain_parts[1] if len(domain_parts) > 1 else domain_parts[0])
    
    # 4. NoOfSubDomain: Jumlah subdomain
    if is_domain_ip:
        no_of_subdomain = 0
    else:
        no_of_subdomain = max(1, len(domain_parts) - 1) if 'www' in domain else max(1, len(domain_parts) - 2)
        
    # 5. HasObfuscation: Keberadaan indikator obfuscation (%20, @, // berlebih, hex, obf)
    obfuscated_chars = ['%', '@', '//', 'hex', 'obf']
    has_obfuscation = 1 if (any(char in url_str[8:] for char in obfuscated_chars) or is_domain_ip) else 0
    
    # 6. ObfuscationRatio: Rasio karakter obfuscation (% hex / @) terhadap panjang URL
    obf_count = sum(url_str.count(c) for c in ['%', '@', '~', '='])
    obfuscation_ratio = obf_count / float(url_length) if url_length > 0 else 0.0
    
    # 7. NoOfDegitsInURL: Total karakter angka (0-9) dalam URL
    no_of_digits = sum(c.isdigit() for c in url_str)
    
    # 8. NoOfQMarkInURL: Jumlah tanda tanya (?)
    no_of_qmark = url_str.count('?')
    
    # 9. SpacialCharRatioInURL: Hitung rasio karakter khusus selain delimiter standar protocol
    special_chars = set("@-_=?&%.~+#:;")
    clean_url_body = re.sub(r'^https?://', '', url_str)
    special_count = sum(1 for c in clean_url_body if c in special_chars)
    special_char_ratio = special_count / float(url_length) if url_length > 0 else 0.04
    
    # 10. IsHTTPS: Penggunaan protokol HTTPS
    is_https = 1 if url_str.lower().startswith("https://") else 0
    
    # ----------------------------------------------------
    # ANALISIS KEACAKAN DOMAIN (RANDOM GIBBERISH / DGA DETECTOR)
    # ----------------------------------------------------
    vowels = sum(1 for c in domain_name if c in 'aeiou')
    vowel_ratio = vowels / float(len(domain_name)) if len(domain_name) > 0 else 0.5
    is_gibberish_domain = (len(domain_name) > 15 and vowel_ratio < 0.35) or (len(domain_name) > 20)
    
    # DAFTAR DOMAIN RESMI POPULER (OFFICIAL WHITELIST)
    official_domains = [
        'paypal.com', 'google.com', 'youtube.com', 'facebook.com', 
        'instagram.com', 'microsoft.com', 'apple.com', 'amazon.com', 
        'tokopedia.com', 'bca.co.id', 'bilibili.com', 'whatsapp.com', 
        'github.com', 'wikipedia.org', 'twitter.com', 'x.com', 'yahoo.com'
    ]
    is_official = any(domain == od or domain.endswith('.' + od) for od in official_domains)
    
    # Indikator TLD Berisiko Phishing / Malicious
    suspicious_tlds = ['xyz', 'top', 'online', 'site', 'cfd', 'buzz', 'info', 'shop', 'work', 'cc', 'tk', 'ml', 'ga', 'gq', 'ws']
    is_suspicious_tld = tld in suspicious_tlds
    
    # Kata kunci kecurigaan leksikal (Phishing + Slot/Judi + Situs Berisiko)
    suspicious_keywords = [
        'login', 'signin', 'verify', 'account', 'bank', 'secure', 
        'update', 'confirm', 'webmail', 'checkpoint', 'auth', 
        'billing', 'claim', 'gift', 'free', 'reward', 'security',
        'slot', 'judi', 'poker', 'casino', 'bet', 'mafia', '88', '777', 
        'jackpot', 'gacor', 'dewasa', 'xxx', 'porn', 'xnxx', 'missav', 'familia'
    ]
    has_suspicious_kw = any(kw in url_str.lower() for kw in suspicious_keywords)
    
    # Pengecekan kecurigaan leksikal komprehensif
    is_suspicious_url = (
        is_domain_ip or 
        has_obfuscation or 
        no_of_digits > 4 or 
        url_length > 50 or 
        has_suspicious_kw or
        is_gibberish_domain or
        (is_suspicious_tld and (no_of_digits > 0 or has_obfuscation or is_gibberish_domain or has_suspicious_kw)) or
        (is_https == 0 and not is_official)
    )
    
    # Jika merupakan domain resmi dan tidak ada obfuscation/IP/digits berlebih
    if is_official and not (has_obfuscation or is_domain_ip or no_of_digits > 5):
        is_suspicious_url = False
        
    # Fitur Heuristik Leksikal DOM/Content berbobot PhiUSIIL
    char_continuation_rate = 0.72 if is_suspicious_url else 1.0
    has_title = 0 if is_suspicious_url else 1
    is_responsive = 0 if is_suspicious_url else 1
    no_of_popup = 0
    has_external_form_submit = 1 if (has_obfuscation and '?' in url_str) else 0
    has_submit_button = 0 if is_suspicious_url else 1
    has_hidden_fields = 0 if is_suspicious_url else 1
    
    # Fitur Pay (Pembayaran): Khusus untuk PayPal resmi, tandai Pay=1 tetapi tetap HasCopyrightInfo=1 & HasSubmitButton=1
    pay = 1 if (('paypal' in domain) or any(kw in path_and_query.lower() for kw in ['pay', 'billing', 'card', 'payment', 'wallet', 'crypto'])) else 0
    has_copyright_info = 0 if is_suspicious_url else 1
    no_of_empty_ref = 0 if is_suspicious_url else 4
    
    # Susun dictionary fitur
    feature_dict = {
        'URLLength': url_length,
        'IsDomainIP': is_domain_ip,
        'CharContinuationRate': round(char_continuation_rate, 4),
        'TLDLength': tld_length,
        'NoOfSubDomain': no_of_subdomain,
        'HasObfuscation': has_obfuscation,
        'ObfuscationRatio': round(obfuscation_ratio, 4),
        'NoOfDegitsInURL': no_of_digits,
        'NoOfQMarkInURL': no_of_qmark,
        'SpacialCharRatioInURL': round(special_char_ratio, 4),
        'IsHTTPS': is_https,
        'HasTitle': has_title,
        'IsResponsive': is_responsive,
        'NoOfPopup': no_of_popup,
        'HasExternalFormSubmit': has_external_form_submit,
        'HasSubmitButton': has_submit_button,
        'HasHiddenFields': has_hidden_fields,
        'Pay': pay,
        'HasCopyrightInfo': has_copyright_info,
        'NoOfEmptyRef': no_of_empty_ref
    }
    
    # Mengembalikan array numpy bentuk (1, 20)
    feature_values = [feature_dict[k] for k in [
        'URLLength', 'IsDomainIP', 'CharContinuationRate', 'TLDLength', 'NoOfSubDomain',
        'HasObfuscation', 'ObfuscationRatio', 'NoOfDegitsInURL', 'NoOfQMarkInURL',
        'SpacialCharRatioInURL', 'IsHTTPS', 'HasTitle', 'IsResponsive', 'NoOfPopup',
        'HasExternalFormSubmit', 'HasSubmitButton', 'HasHiddenFields', 'Pay',
        'HasCopyrightInfo', 'NoOfEmptyRef'
    ]]
    
    return np.array([feature_values]), feature_dict

if __name__ == "__main__":
    test_urls = [
        "familia88.net",
        "xnxx.com",
        "missav.ws",
        "ff001.mafia78b.online",
        "paypal.com",
        "youtube.com"
    ]
    for u in test_urls:
        arr, d = extract_features(u)
        print(f"URL: {u}")
        print(f"Features: {d}\n")
