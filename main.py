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

app = FastAPI(title="AI Log Scanner & GeoIP API", version="1.15.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE = '/var/log/nginx/cs_ssl_access.log'
OUTPUT_JSON = '/app/data/security-data.json'
OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://172.17.0.1:11434/api/generate')

# สร้าง Lock ป้องกันไม่ให้ AI ทำงานซ้อนกันหลาย Thread พร้อมกัน
ai_lock = threading.Lock()

def parse_device_type(user_agent):
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

def get_ip_country(ip):
    """ค้นหาประเทศจาก IP Address ผ่าน ip-api.com"""
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2)
        if res.status_code == 200:
            country = res.json().get('countryCode')
            if country:
                return country
    except Exception:
        pass
        
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        return 'LOCAL'
    return 'UNKNOWN'

def run_ai_scanner():
    print(f"[{datetime.now()}] Starting Full Log Scan & AI Dynamic Analysis...")
    
    result = {
        "threat_level": "LOW",
        "total_requests": 0,
        "ai_summary": "AI กำลังวิเคราะห์พฤติกรรมจาก Log ล่าสุด...",
        "detected_attacks": [],
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "charts": {
            "traffic_by_country": {"labels": [], "data": []},
            "top_ips": {"labels": [], "data": []},
            "traffic_by_device": {"labels": [], "data": []}
        }
    }

    try:
        if not os.path.exists(LOG_FILE):
            print(f"[{datetime.now()}] Error: Log file not found at {LOG_FILE}")
            return result

        # 1. อ่าน Log ทั้งหมดเพื่อทำสถิติภาพรวม
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            print(f"[{datetime.now()}] Log file is empty.")
            return result

        result['total_requests'] = len(lines)

        ip_list = []
        device_list = []

        for line in lines:
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_list.append(ip)
                
                ua_match = re.findall(r'"([^"]*)"', line)
                user_agent = ua_match[-1] if ua_match else ''
                device_list.append(parse_device_type(user_agent))

        ip_counts = Counter(ip_list)
        device_counts = Counter(device_list)
        country_counts = Counter()
        ip_country_map = {}

        for ip in ip_counts.keys():
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

        # บันทึกสถิติกราฟลงไฟล์ JSON ก่อนทันทีเพื่อให้ UI แสดงผลไว
        result['last_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)

        # 2. กรองข้อมูลเฉพาะ Request สำคัญจาก 15 บรรทัดล่าสุด
        ai_lines_chunk = lines[-15:]
        simplified_logs = []
        for line in ai_lines_chunk:
            parts = re.findall(r'"([^"]*)"', line)
            if parts:
                simplified_logs.append(parts[0])

        def background_ai_analysis(clean_logs, country_map, current_result):
            if not ai_lock.acquire(blocking=False):
                print(f"[{datetime.now()}] AI is already running, skipping this background task.")
                return
            
            try:
                # แก้ไขจุดที่เกิด Error โดยการแปลง list เป็น string ภายนอก f-string ก่อน
                joined_logs = "\n".join(clean_logs)
                
                prompt = (
                    "You are a system log analyzer. Review these web server request paths and write a concise 1-sentence Thai summary about the website traffic activity (e.g., page views or asset loading). Do not hallucinate or invent stories.\n\n"
                    f"Requests:\n{joined_logs}\n\n"
                    "Return ONLY a JSON object:\n"
                    '{"summary": "เขียนสรุปภาษาไทยสั้นๆ ตรงประเด็น"}'
                )

                response = requests.post(OLLAMA_URL, json={
                    "model": "qwen2.5:1.5b",
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "num_predict": 96
                    }
                }, timeout=120)
                
                print(f"[{datetime.now()}] AI Raw Response Status: {response.status_code}")
                print(f"[{datetime.now()}] AI Raw Response: {response.text}")
                
                if response.status_code == 200:
                    res_data = response.json()
                    raw_text = res_data.get('response', '{}').strip()
                    clean_text = re.sub(r'^```json\s*|\s*```$', '', raw_text, flags=re.MULTILINE).strip()
                    
                    try:
                        ai_json = json.loads(clean_text)
                        summary_text = ai_json.get('summary', '')
                        if summary_text:
                            current_result['ai_summary'] = summary_text
                            current_result['threat_level'] = "LOW"
                            
                            with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
                                json.dump(current_result, f, ensure_ascii=False, indent=4)
                    except Exception:
                        if raw_text:
                            current_result['ai_summary'] = raw_text[:100]
                            with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
                                json.dump(current_result, f, ensure_ascii=False, indent=4)
                                
            except Exception as ai_err:
                print(f"[{datetime.now()}] AI Background Error: {ai_err}")
            finally:
                ai_lock.release()

        ai_thread = threading.Thread(target=background_ai_analysis, args=(simplified_logs, ip_country_map, result), daemon=True)
        ai_thread.start()

    except Exception as e:
        print(f"[{datetime.now()}] Scan Error: {e}")

    return result

def auto_scan_scheduler():
    time.sleep(5)
    while True:
        run_ai_scanner()
        time.sleep(900)

@app.on_event("startup")
def startup_event():
    thread = threading.Thread(target=auto_scan_scheduler, daemon=True)
    thread.start()

@app.get("/")
def root():
    return {"status": "online", "service": "AI Log Scanner & GeoIP API"}

@app.get("/api/v1/security/summary")
def get_security_summary():
    if os.path.exists(OUTPUT_JSON):
        with open(OUTPUT_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    return run_ai_scanner()

@app.post("/api/v1/security/scan-now")
def trigger_scan():
    thread = threading.Thread(target=run_ai_scanner)
    thread.start()
    return {"message": "Scan triggered successfully", "status": "processing"}
