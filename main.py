import os
import re
import json
import requests
import threading
import time
from datetime import datetime
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# โหลด Environment Variables จากไฟล์ .env
load_dotenv()

app = FastAPI(title="AI Log Scanner & GeoIP API (Gemini Powered)", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE = os.getenv('LOG_FILE', '/var/log/nginx/cs_ssl_access.log')
OUTPUT_JSON = os.getenv('OUTPUT_JSON', '/app/data/security-data.json')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '').strip()
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash').strip()

# สร้าง Lock ป้องกันไม่ให้ AI ทำงานซ้อนกันหลาย Thread พร้อมกัน
ai_lock = threading.Lock()

# กฎสำหรับตรวจจับพฤติกรรมและการโจมตีที่น่าสงสัย (Heuristic Rules)
SUSPICIOUS_PATTERNS = [
    (r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)', 'Path Traversal / LFI'),
    (r'(\.env|\.git|\.aws|wp-config\.php|/etc/passwd|win\.ini)', 'Sensitive File Disclosure'),
    (r'(wp-admin|wp-login|phpmyadmin|/actuator|/manager/html|shell\.php)', 'Admin / Vulnerability Scan'),
    (r'(union\s+select|select\s+.*\s+from|\bexec\s*\(|\bwaitfor\s+delay|\'\s*or\s*\'1\'=\'1)', 'SQL Injection'),
    (r'(<script|javascript:|onerror\s*=|onload\s*=|eval\s*\()', 'Cross-Site Scripting (XSS)'),
    (r'(;\s*(cat|ls|curl|wget|id|whoami|bash|sh|nc)\b|\$\(.*\)|`.*`)', 'Command Injection'),
    (r'(sqlmap|nikto|dirbuster|gobuster|masscan|nmap|acunetix|zgrab)', 'Automated Security Scanner'),
]

def parse_device_type(user_agent: str) -> str:
    """จำแนกประเภทอุปกรณ์จาก User-Agent String"""
    ua = user_agent.lower()
    if any(bot in ua for bot in ['bot', 'crawler', 'spider', 'curl', 'python', 'postman', 'wget']):
        return 'Bot/Script'
    elif any(mobile in ua for mobile in ['iphone', 'android', 'mobile', 'ipod']):
        return 'Mobile'
    elif any(tablet in ua for tablet in ['ipad', 'tablet']):
        return 'Tablet'
    elif any(desktop in ua for desktop in ['windows', 'macintosh', 'linux', 'x11']):
        return 'Desktop'
    return 'Other'

def get_ip_country(ip: str) -> str:
    """ค้นหาประเทศจาก IP Address ผ่าน ip-api.com"""
    if ip.startswith(('127.', '192.168.', '10.', '172.', 'fc00:', 'fe80:')) or ip in ('::1', 'localhost'):
        return 'LOCAL'
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2)
        if res.status_code == 200:
            country = res.json().get('countryCode')
            if country:
                return country
    except Exception:
        pass
    return 'UNKNOWN'

def parse_nginx_log_line(line: str) -> dict:
    """แปลงบรรทัด Log Nginx ให้เป็น Dictionary โครงสร้างมาตรฐาน"""
    log_pattern = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
    )
    match = log_pattern.match(line)
    if match:
        request_line = match.group(3)
        req_parts = request_line.split()
        method = req_parts[0] if len(req_parts) > 0 else 'UNKNOWN'
        path = req_parts[1] if len(req_parts) > 1 else ''
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'request': request_line,
            'method': method,
            'path': path,
            'status': int(match.group(4)),
            'bytes': match.group(5),
            'referer': match.group(6),
            'user_agent': match.group(7),
            'raw': line
        }
    
    # Fallback Parser สำหรับรูปแบบที่อาจแตกต่างเล็กน้อย
    ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
    ip = ip_match.group(1) if ip_match else 'UNKNOWN'
    quotes = re.findall(r'"([^"]*)"', line)
    req = quotes[0] if quotes else ''
    ua = quotes[-1] if len(quotes) > 1 else ''
    
    status_match = re.search(r'\s(\d{3})\s', line)
    status = int(status_match.group(1)) if status_match else 200
    
    return {
        'ip': ip,
        'timestamp': '',
        'request': req,
        'method': req.split()[0] if req else 'UNKNOWN',
        'path': req.split()[1] if len(req.split()) > 1 else req,
        'status': status,
        'bytes': '0',
        'referer': '',
        'user_agent': ua,
        'raw': line
    }

def analyze_with_gemini(parsed_logs: list, suspicious_logs: list, stats_summary: dict) -> dict:
    """เรียกใช้ Google Gemini API เพื่อวิเคราะห์พฤติกรรมความปลอดภัยและภัยคุกคามจริง"""
    api_key = os.getenv('GEMINI_API_KEY', '').strip()
    model_name = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash').strip()

    if not api_key:
        print(f"[{datetime.now()}] Warning: GEMINI_API_KEY not set. Using heuristic fallback.")
        return fallback_heuristic_analysis(suspicious_logs, stats_summary)

    # จัดเตรียมข้อมูล Log ตัวอย่างและ Log ที่น่าสงสัยเพื่อส่งให้ Gemini
    formatted_suspicious = []
    for item in suspicious_logs[:40]:  # จำกัดจำนวนเพื่อความกระชับและประหยัด Token
        formatted_suspicious.append(
            f"IP: {item.get('ip')} | Status: {item.get('status')} | UA: {item.get('user_agent')[:60]} | Request: {item.get('request')}"
        )
    
    normal_sample = []
    for item in parsed_logs[-20:]:
        normal_sample.append(f"{item.get('ip')} - {item.get('status')} - {item.get('request')}")

    prompt = f"""You are a Lead SOC Cybersecurity Analyst. Analyze the following web server access logs and identify actual cyber threats, scanning activity, attack patterns, and overall system security posture.

TRAFFIC OVERVIEW:
- Total Requests: {stats_summary.get('total_requests', 0)}
- Suspicious Flagged Requests: {len(suspicious_logs)}
- Status Code Distribution: {stats_summary.get('status_distribution', {})}
- Top Client IPs: {stats_summary.get('top_ips', {})}

SUSPICIOUS REQUESTS DETECTED:
{chr(10).join(formatted_suspicious) if formatted_suspicious else "No obvious pattern matches detected."}

SAMPLE RECENT TRAFFIC:
{chr(10).join(normal_sample) if normal_sample else "No traffic"}

INSTRUCTIONS:
1. Determine the overall threat level: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
2. Write a professional, concise executive summary in Thai (ai_summary) explaining what traffic and threats were observed.
3. List any specific detected attacks in 'detected_attacks' with attack type, severity, attacker IP, attacked target path, Thai description, and mitigation recommendation.
4. If traffic is clean/normal, threat_level should be "LOW" and detected_attacks should be an empty list [].

Output strictly valid JSON with this exact schema:
{{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "ai_summary": "สรุปสถานการณ์ความปลอดภัยภาษาไทยที่ชัดเจน ตรงไปตรงมา",
  "detected_attacks": [
    {{
      "type": "Attack Name (e.g., SQL Injection, Sensitive File Scanning, Brute Force)",
      "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "source_ip": "attacker IP",
      "target_path": "targeted endpoint/path",
      "description": "คำอธิบายพฤติกรรมและระดับความเสี่ยงเป็นภาษาไทย",
      "recommendation": "คำแนะนำการรับมือและป้องกัน เช่น แนะนำบล็อก IP หรือตั้งค่า Firewall"
    }}
  ]
}}
"""

    # เรียกใช้ Google Gemini API
    # 1. ลองผ่าน google-genai SDK
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            )
        )
        if response.text:
            return json.loads(response.text)
    except Exception as sdk_err:
        print(f"[{datetime.now()}] Gemini SDK call failed ({sdk_err}), trying REST API fallback...")

    # 2. REST API Fallback
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2
            }
        }
        res = requests.post(url, headers=headers, json=payload, timeout=30)
        if res.status_code == 200:
            data = res.json()
            text_content = data['candidates'][0]['content']['parts'][0]['text']
            return json.loads(text_content)
        else:
            print(f"[{datetime.now()}] Gemini REST Error {res.status_code}: {res.text}")
    except Exception as rest_err:
        print(f"[{datetime.now()}] Gemini REST API error: {rest_err}")

    return fallback_heuristic_analysis(suspicious_logs, stats_summary)

def fallback_heuristic_analysis(suspicious_logs: list, stats_summary: dict) -> dict:
    """การวิเคราะห์ฉุกเฉินด้วยกฎ Heuristic Rule กรณีไม่ได้ตั้งค่า Gemini API Key หรือต่อเน็ตไม่ได้"""
    total_suspicious = len(suspicious_logs)
    if total_suspicious == 0:
        return {
            "threat_level": "LOW",
            "ai_summary": "ระบบตรวจไม่พบพฤติกรรมน่าสงสัย การเข้าชมเว็บไซต์อยู่ในเกณฑ์ปกติ (Heuristic Fallback)",
            "detected_attacks": []
        }
    
    threat_level = "LOW"
    if total_suspicious > 20:
        threat_level = "CRITICAL"
    elif total_suspicious > 5:
        threat_level = "HIGH"
    elif total_suspicious > 0:
        threat_level = "MEDIUM"

    attacks = []
    seen = set()
    for item in suspicious_logs[:10]:
        key = (item.get('ip'), item.get('path'))
        if key in seen:
            continue
        seen.add(key)
        attacks.append({
            "type": item.get('detected_reason', 'Suspicious Activity'),
            "severity": "HIGH" if threat_level in ["HIGH", "CRITICAL"] else "MEDIUM",
            "source_ip": item.get('ip', 'UNKNOWN'),
            "target_path": item.get('path', ''),
            "description": f"ตรวจพบการพยายามเข้าถึงหรือส่ง payload ที่ผิดปกติ: {item.get('request', '')}",
            "recommendation": f"ตรวจสอบ IP {item.get('ip')} และพิจารณาบล็อกที่ Firewall หรือ WAF"
        })

    summary = (
        f"ตรวจพบการโจมตีหรือการสแกนช่องโหว่จำนวน {total_suspicious} ครั้ง "
        f"ระดับความเสี่ยงอยู่ที่ {threat_level} แนะนำให้ตรวจสอบรายการ IP ที่น่าสงสัย"
    )
    if not os.getenv('GEMINI_API_KEY'):
        summary += " (หมายเหตุ: กรุณาระบุ GEMINI_API_KEY ใน .env เพื่อใช้งานการวิเคราะห์เชิงลึกด้วย AI)"

    return {
        "threat_level": threat_level,
        "ai_summary": summary,
        "detected_attacks": attacks
    }

def run_ai_scanner():
    """ฟังก์ชันหลักสำหรับอ่าน Log ประมวลผลสถิติ และสั่งวิเคราะห์ความปลอดภัย"""
    print(f"[{datetime.now()}] Starting Full Log Scan & Security Threat Analysis...")
    
    result = {
        "threat_level": "LOW",
        "total_requests": 0,
        "ai_summary": "ระบบกำลังเริ่มการวิเคราะห์ Log...",
        "detected_attacks": [],
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "charts": {
            "traffic_by_country": {"labels": [], "data": []},
            "top_ips": {"labels": [], "data": []},
        }
    }

    try:
        target_log_file = LOG_FILE
        # ตรวจสอบกรณี path ไม่มีอยู่จริง หรือ Docker เมานต์เป็นโฟลเดอร์แทนไฟล์
        if not os.path.exists(target_log_file) or os.path.isdir(target_log_file):
            fallback_candidates = [
                '/app/data/mock_access.log',
                os.path.join(os.path.dirname(OUTPUT_JSON), 'mock_access.log'),
                './data/mock_access.log'
            ]
            found_fallback = next((cand for cand in fallback_candidates if os.path.isfile(cand)), None)
            
            if found_fallback:
                print(f"[{datetime.now()}] Notice: {target_log_file} is a directory or missing. Auto-fallback to: {found_fallback}")
                target_log_file = found_fallback
            else:
                err_msg = f"ไม่พบไฟล์ Log หรือตำแหน่ง {target_log_file} เป็นโฟลเดอร์ (แนะนำให้ใช้ ./data/mock_access.log สำหรับ Local)"
                print(f"[{datetime.now()}] Error: {err_msg}")
                result["ai_summary"] = err_msg
                return result

        # 1. อ่านไฟล์ Log ทั้งหมด
        with open(target_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            print(f"[{datetime.now()}] Log file is empty.")
            result["ai_summary"] = "ไฟล์ Log ว่างเปล่า ยังไม่มีทราฟฟิกเข้ามาในระบบ"
            return result

        result['total_requests'] = len(lines)

        # 2. แปลง Log เป็นโครงสร้างและคำนวณสถิติ
        parsed_logs = []
        suspicious_logs = []
        ip_list = []
        device_list = []
        status_counts = Counter()

        for line in lines:
            parsed = parse_nginx_log_line(line)
            parsed_logs.append(parsed)
            ip_list.append(parsed['ip'])
            device_list.append(parse_device_type(parsed['user_agent']))
            status_counts[parsed['status']] += 1

            # ตรวจสอบกับ Suspicious Patterns
            target_str = f"{parsed['request']} {parsed['user_agent']}".lower()
            detected_reason = None
            for pattern, reason in SUSPICIOUS_PATTERNS:
                if re.search(pattern, target_str, re.IGNORECASE):
                    detected_reason = reason
                    break
            
            if detected_reason or parsed['status'] in (401, 403, 500):
                parsed_copy = dict(parsed)
                parsed_copy['detected_reason'] = detected_reason or f"HTTP {parsed['status']} Error Spike"
                suspicious_logs.append(parsed_copy)

        ip_counts = Counter(ip_list)
        device_counts = Counter(device_list)
        country_counts = Counter()
        ip_country_map = {}

        # ค้นหาประเทศของ Top IPs
        for ip in list(ip_counts.keys())[:50]:
            country = get_ip_country(ip)
            ip_country_map[ip] = country
            country_counts[country] += ip_counts[ip]

        result['charts'] = {
            "traffic_by_country": {
                "labels": list(country_counts.keys()) if country_counts else ["UNKNOWN"],
                "data": list(country_counts.values()) if country_counts else [len(lines)]
            },
            "top_ips": {
                "labels": list(ip_counts.keys())[:5],
                "data": list(ip_counts.values())[:5]
            },
            "traffic_by_device": {
                "labels": list(device_counts.keys()),
                "data": list(device_counts.values())
            }
        }

        # บันทึกสถิติกราฟเบื้องต้นลง JSON ก่อน
        result['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)

        stats_summary = {
            "total_requests": len(lines),
            "status_distribution": dict(status_counts),
            "top_ips": dict(ip_counts.most_common(5))
        }

        # 3. รันการวิเคราะห์ AI ใน Background Thread
        def background_ai_worker(logs, susp, stats, current_result):
            if not ai_lock.acquire(blocking=False):
                print(f"[{datetime.now()}] AI Analysis is already running. Skipping this cycle.")
                return
            
            try:
                ai_output = analyze_with_gemini(logs, susp, stats)
                if ai_output and isinstance(ai_output, dict):
                    current_result['threat_level'] = ai_output.get('threat_level', 'LOW')
                    current_result['ai_summary'] = ai_output.get('ai_summary', '')
                    current_result['detected_attacks'] = ai_output.get('detected_attacks', [])
                    current_result['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
                        json.dump(current_result, f, ensure_ascii=False, indent=4)
                    print(f"[{datetime.now()}] AI Threat Analysis completed. Threat Level: {current_result['threat_level']}")
            except Exception as ai_err:
                print(f"[{datetime.now()}] Error in background AI worker: {ai_err}")
            finally:
                ai_lock.release()

        ai_thread = threading.Thread(
            target=background_ai_worker,
            args=(parsed_logs, suspicious_logs, stats_summary, result),
            daemon=True
        )
        ai_thread.start()

    except Exception as e:
        print(f"[{datetime.now()}] Scan Error: {e}")

    return result

def auto_scan_scheduler():
    """สแกนอัตโนมัติทุกๆ 15 นาที"""
    time.sleep(5)
    while True:
        try:
            run_ai_scanner()
        except Exception as e:
            print(f"[{datetime.now()}] Scheduler Error: {e}")
        time.sleep(900)

@app.on_event("startup")
def startup_event():
    thread = threading.Thread(target=auto_scan_scheduler, daemon=True)
    thread.start()

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "AI Log Scanner & GeoIP API (Gemini Powered)",
        "version": "2.0.0",
        "gemini_enabled": bool(os.getenv('GEMINI_API_KEY'))
    }

@app.get("/api/v1/security/summary")
def get_security_summary():
    """ดึงข้อมูลผลการสแกนความปลอดภัยล่าสุด"""
    if os.path.exists(OUTPUT_JSON):
        with open(OUTPUT_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    return run_ai_scanner()

@app.post("/api/v1/security/scan-now")
def trigger_scan():
    """สั่งให้ระบบเริ่มทำการสแกนและวิเคราะห์ทันที"""
    thread = threading.Thread(target=run_ai_scanner)
    thread.start()
    return {"message": "Scan and Gemini Threat Analysis triggered successfully", "status": "processing"}
