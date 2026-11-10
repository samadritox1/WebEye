#!/usr/bin/env python3
import uvicorn
from app.config import settings

def main():
    print(r"""
    ===================================================================
     __        __   _     _____
     \ \      / /__| |__ | ____|_   _  ___
      \ \ /\ / / _ \ '_ \|  _| | | | |/ _ \
       \ V  V /  __/ |_) | |___| |_| |  __/
        \_/\_/ \___|_.__/|_____|\__, |\___|
                                |___/
      WebEye — Cyber Threat Intelligence & Phishing Defense Platform
    ===================================================================
    [+] Server initializing on http://127.0.0.1:8000
    [+] Swagger REST API Docs at http://127.0.0.1:8000/docs
    [+] API v1, Async Batch Queue & MITRE ATT&CK Active
    ===================================================================
    """)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()
