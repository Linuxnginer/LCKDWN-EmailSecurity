from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import requests
import whois

from sec import (
    analyze_domain,
    analyze_ip,
    analyze_email,
    parse_email_header,
    check_phishing,
    calculate_risk_score,
    generate_ai_insights,
    is_ip,
    is_email
)

app = FastAPI(title="LCKDWN Security Scanner")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None, "error": None})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, target: str = Form(...)):
    target = target.strip()
    if not target:
        return templates.TemplateResponse("index.html", {"request": request, "result": None, "error": "Input cannot be empty."})

    try:
        normalized = target.replace("\r\n", "\n")
        is_header = "\n" in normalized and ":" in normalized and "received:" in normalized.lower()

        # --------------------------
        # Email Header Analysis
        # --------------------------
        if is_header:
            headers = parse_email_header(normalized)
            issues = check_phishing(headers)
            risk_score = calculate_risk_score(issues)
            ai_insights = generate_ai_insights(issues)
            results = {
                "type": "email_header",
                "parsed_header": headers,
                "phishing_issues": issues,
                "risk_score": risk_score,
                "ai_insights": ai_insights
            }

        # --------------------------
        # IP Analysis
        # --------------------------
        elif is_ip(target):
            ip_info = analyze_ip(target)
            results = {"type": "ip", "ip_info": ip_info}

        # --------------------------
        # Email Address Analysis
        # --------------------------
        elif is_email(target):
            email_info = analyze_email(target)
            results = {"type": "email", "email_info": email_info}

        # --------------------------
        # Domain Analysis
        # --------------------------
        else:
            domain_info = analyze_domain(target)

            # WHOIS
            try:
                w = whois.whois(target)
                domain_info["whois"] = {
                    "registrant": w.get("registrant_name"),
                    "org": w.get("org"),
                    "country": w.get("country"),
                    "creation_date": str(w.get("creation_date")),
                    "expiration_date": str(w.get("expiration_date"))
                }
            except:
                domain_info["whois"] = "Not available"

            # Geo-location for all A records
            geo_info = []
            for ip in domain_info.get("A", []):
                try:
                    r = requests.get(f"https://ipwho.is/{ip}").json()
                    geo_info.append({
                        "ip": ip,
                        "country": r.get("country"),
                        "city": r.get("city"),
                        "isp": r.get("isp"),
                        "latitude": r.get("latitude"),
                        "longitude": r.get("longitude")
                    })
                except:
                    geo_info.append({"ip": ip, "error": "Could not fetch location"})
            domain_info["geo_info"] = geo_info

            results = {"type": "domain", "domain_info": domain_info}

    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "result": None, "error": f"Processing error: {str(e)}"}
        )

    return templates.TemplateResponse("index.html", {"request": request, "result": results, "error": None})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
