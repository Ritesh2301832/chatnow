# ChatNow deployment

## Local test
Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DEV_MODE="true"
python server.py
```
Open http://127.0.0.1:8000

DEV_MODE is only for testing because this project currently has no real email OTP provider.

## Render
Create a Web Service from this folder/repository.
Build: `pip install -r requirements.txt`
Start: `uvicorn server:app --host 0.0.0.0 --port $PORT`

Important: `users.json` is file storage and may not persist reliably on free/ephemeral hosting. For a real public service, use a database and a real email/OTP provider.
