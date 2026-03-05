import re
import socket
import email
from email import policy
import dns.resolver
import whois
from ipwhois import IPWhois
import spf
import requests

# -------------------------
# Utility Functions
# -------------------------
def is_ip(value):
    ipv4 = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6 = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    return re.match(ipv4, value) or re.match(ipv6, value)

def is_email(value):
    pattern = r"^[^@]+@[^@]+\.[^@]+$"
    return re.match(pattern, value)

def is_local_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")

# -------------------------
# IP Geolocation Helper
# -------------------------
def geolocate_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp")
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp")
            }
    except:
        pass
    return {"country": "Unknown", "city": None, "isp": None}

# -------------------------
# Domain Analysis
# -------------------------
def analyze_domain(domain):
    result = {"domain": domain, "A": [], "MX": [], "TXT": [], "whois": None, "geo_info": []}

    # DNS Records
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["A"] = [str(rdata) for rdata in answers]
    except: pass

    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["MX"] = [str(rdata.exchange) for rdata in answers]
    except: pass

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        result["TXT"] = [b"".join(rdata.strings).decode() for rdata in answers]
    except: pass

    # WHOIS
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
        }
    except Exception as e:
        result["whois"] = f"WHOIS lookup failed: {str(e)}"

    # Geolocation for A records
    for ip in result["A"]:
        geo = geolocate_ip(ip)
        result["geo_info"].append({
            "ip": ip,
            "country": geo.get("country"),
            "city": geo.get("city"),
            "isp": geo.get("isp")
        })

    return result

# -------------------------
# IP Analysis
# -------------------------
def analyze_ip(ip):
    result = {"ip": ip, "PTR": None, "ASN": None, "country": None, "city": None, "isp": None}

    try: result["PTR"] = socket.gethostbyaddr(ip)[0]
    except: pass

    try:
        obj = IPWhois(ip)
        info = obj.lookup_rdap()
        result["ASN"] = info.get("asn")
        network = info.get("network", {})
        result["country"] = network.get("country")
    except: pass

    geo = geolocate_ip(ip)
    for key in ["country", "city", "isp"]:
        if not result.get(key):
            result[key] = geo.get(key)

    return result

# -------------------------
# Email Address Analysis
# -------------------------
def analyze_email(email_addr, sender_ip="8.8.8.8"):
    domain = email_addr.split("@")[-1]
    result = analyze_domain(domain)
    try:
        status, msg = spf.check2(i=sender_ip, s=email_addr, h=domain)
        result["SPF"] = {"status": status, "message": msg}
    except: pass
    return result

# -------------------------
# Email Header Analysis
# -------------------------
def parse_email_header(raw_header):
    raw_header = raw_header.replace("\r\n", "\n")
    header_only = raw_header.split("\n\n", 1)[0]
    msg = email.message_from_string(header_only, policy=policy.default)
    return {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "reply_to": msg.get("Reply-To"),
        "received": msg.get_all("Received", []),
        "dkim": msg.get("DKIM-Signature"),
        "auth_results": msg.get("Authentication-Results")
    }

def trace_true_ip(received_headers):
    ip_pattern = r"\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]"
    for header in reversed(received_headers):
        matches = re.findall(ip_pattern, header)
        for ip in matches:
            if not is_local_ip(ip):
                return ip
    return None

def check_dmarc_alignment(auth_results):
    if not auth_results:
        return False
    return "dmarc=fail" in auth_results.lower()

def check_spf_dkim_alignment(headers):
    from_domain = ""
    if headers.get("from") and "@" in headers["from"]:
        from_domain = headers["from"].split("@")[-1].lower()
    auth = (headers.get("auth_results") or "").lower()
    spf_aligned = "spf=pass" in auth and from_domain in auth
    dkim_aligned = "dkim=pass" in auth and from_domain in auth
    return spf_aligned, dkim_aligned

def check_phishing(headers):
    phishing_flags = []
    from_domain = ""
    if headers.get("from") and "@" in headers["from"]:
        from_domain = headers["from"].split("@")[-1]

    if headers.get("reply_to") and from_domain:
        reply_domain = headers["reply_to"].split("@")[-1]
        if reply_domain.lower() != from_domain.lower():
            phishing_flags.append("Reply-To domain mismatch")

    auth = headers.get("auth_results") or ""
    if "spf=pass" not in auth.lower(): phishing_flags.append("SPF check failed")
    if not headers.get("dkim"): phishing_flags.append("Missing DKIM signature")
    if check_dmarc_alignment(auth): phishing_flags.append("DMARC alignment failed")
    true_ip = trace_true_ip(headers.get("received", []))
    if true_ip: phishing_flags.append(f"True sending IP: {true_ip}")
    spf_aligned, dkim_aligned = check_spf_dkim_alignment(headers)
    if not spf_aligned: phishing_flags.append("SPF not aligned with From domain")
    if not dkim_aligned: phishing_flags.append("DKIM not aligned with From domain")

    return phishing_flags

# -------------------------
# New: Risk Score & AI Analysis
# -------------------------
def calculate_risk_score(phishing_issues):
    score = 0
    for issue in phishing_issues:
        if "SPF not aligned" in issue or "DKIM not aligned" in issue or "DMARC" in issue:
            score += 2
        else:
            score += 1
    return min(score, 5)

def generate_ai_insights(phishing_issues):
    insights = []
    for issue in phishing_issues:
        if "SPF" in issue:
            insights.append("SPF failed: email may not be from authorized server.")
        elif "DKIM" in issue:
            insights.append("DKIM missing or misaligned: signature not verified.")
        elif "DMARC" in issue:
            insights.append("DMARC failure: domain policy not followed.")
        elif "True sending IP" in issue:
            insights.append(f"True sending IP detected; check if trusted.")
        else:
            insights.append(issue)
    return insights
