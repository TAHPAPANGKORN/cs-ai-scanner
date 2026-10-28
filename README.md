# cs-ai-scanner

Service วิเคราะห์ Nginx Access Log แบบอัตโนมัติด้วย FastAPI และ Google Gemini API โดยจัดกลุ่มสถิติทราฟฟิก สกัดรูปแบบการโจมตี (Heuristic rules) และส่งให้ LLM สรุปรายงานสถานะความปลอดภัยในรูปแบบ JSON

---

## Architecture

- **Log Parser & Heuristic Filter:** สกัดข้อมูล IP, Status, User-Agent, Path และตรวจจับ Signatures เช่น SQL Injection, Path Traversal, Sensitive files (`.env`, `.git`, `wp-config`), Admin scans และ Scanner bots
- **AI Security Engine:** ส่งสถิติภาพรวมและ Log ที่น่าสงสัยไปยัง Gemini API เพื่อประเมินระดับความเสี่ยง (`threat_level`) และสร้างคำแนะนำการป้องกัน
- **Failover & Timeout:** เรียกผ่าน REST API พร้อมกำหนด Socket Timeout 20 วินาที เพื่อป้องกัน Thread ค้าง และมีระบบสลับโมเดลอัตโนมัติ (`gemini-3.1-flash-lite` -> `gemini-3.5-flash`)
- **Background Worker:** สแกนอัตโนมัติทุก 15 นาที และรองรับการ Trigger ผ่าน API ทันที

---

## Setup & Running

### 1. Configuration

สร้างไฟล์ `.env` จากตัวอย่าง:

```bash
cp .env.example .env
```

กำหนดค่าตัวแปรใน `.env`:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3.1-flash-lite

# Production (Linux)
HOST_LOG_PATH=/var/log/nginx/cs_ssl_access.log
LOG_FILE=/var/log/nginx/cs_ssl_access.log

# Local Dev
# HOST_LOG_PATH=./data/mock_access.log
# LOG_FILE=/app/data/mock_access.log

OUTPUT_JSON=/app/data/security-data.json
```

### 2. Start Service

```bash
docker compose up -d --build
```

---

## API Reference

API ให้บริการที่พอร์ต `1234` (Swagger UI: `http://localhost:1234/docs`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Service health status |
| `GET` | `/api/v1/security/summary` | อ่านผลวิเคราะห์ความปลอดภัยและสถิติล่าสุด |
| `POST` | `/api/v1/security/scan-now` | สั่งเริ่มประมวลผล Log และ AI ทันที |

### Example Request

```bash
curl -X POST http://localhost:1234/api/v1/security/scan-now
curl -s http://localhost:1234/api/v1/security/summary | jq .
```

---

## Output Schema

ไฟล์ผลลัพธ์จัดเก็บที่ `/app/data/security-data.json`:

```json
{
  "threat_level": "LOW",
  "total_requests": 33,
  "ai_summary": "สรุปสถานะความปลอดภัยและพฤติกรรมทราฟฟิกโดย AI",
  "detected_attacks": [
    {
      "type": "SQL Injection",
      "severity": "HIGH",
      "source_ip": "198.51.100.45",
      "target_path": "/api/users?id=1' UNION SELECT...",
      "description": "คำอธิบายพฤติกรรมที่ตรวจพบ",
      "recommendation": "คำแนะนำการรับมือ เช่น บล็อก IP หรือตั้งค่า WAF"
    }
  ],
  "last_updated": "2026-10-28 04:07:32",
  "charts": {
    "traffic_by_country": { "labels": ["TH"], "data": [33] },
    "top_ips": { "labels": ["223.205.27.198"], "data": [33] },
    "traffic_by_device": { "labels": ["Desktop"], "data": [33] }
  }
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | *(Required)* | Google Gemini API Key จาก Google AI Studio |
| `GEMINI_MODEL` | `gemini-3.1-flash-lite` | โมเดลหลักที่ใช้ในการวิเคราะห์ |
| `HOST_LOG_PATH` | `/var/log/nginx/cs_ssl_access.log` | Path ของ Log บน Host OS |
| `LOG_FILE` | `/var/log/nginx/cs_ssl_access.log` | Path ของ Log ภายใน Container |
| `OUTPUT_JSON` | `/app/data/security-data.json` | Path สำหรับบันทึกไฟล์ผลลัพธ์ |

---
เขียนด้วย Gemini 3.8 Flash
