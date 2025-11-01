# Flask-Todo-App

Simple Flask todo app with register/login, dashboard, add/edit/delete, toggle active/inactive state, search and sort. Uses Bootstrap for an attractive UI.

Quick start (PowerShell):

```powershell
cd c:\Users\hp\Desktop\todo
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

Notes:
- Database is SQLite at `instance/app.db` (created next to `app.py`).
- Change `SECRET_KEY` in `app.py` before deploying.
