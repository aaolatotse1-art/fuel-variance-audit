# Fuel Variance Audit (FVA)

A web-based fuel variance audit and reporting system for transport fleet operations. Tracks loading vs. offloading volumes across trips, flags anomalies, and provides role-based access for dispatch, management, and executives.

---

## Features

- **Fuel Variance Tracking** — Compare loaded vs. offloaded volumes per trip; auto-flag trips that exceed product tolerance thresholds
- **Analytics Dashboard** — Contract performance, product breakdown, offloading depot analysis, day-of-week trends, gain/loss by vehicle, and gain/loss by loading point
- **Analytics Summary Report** — Full-screen printable report with seasonal gain/loss chart (Canvas2D)
- **Role-Based Access Control** — Five roles with granular permissions:

  | Role | Upload | Delete | Export | Reports | Investigate | Admin |
  |------|--------|--------|--------|---------|-------------|-------|
  | Administrator | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
  | Dispatch | ✓ | — | ✓ | ✓ | — | — |
  | Exco | — | — | ✓ | — | — | — |
  | Head of Dept | — | — | ✓ | — | — | — |
  | Viewer | — | — | — | — | — | — |

- **Driver Statement Flow** — Send a pre-filled Zoho Form link to a driver via email (EmailJS) directly from a trip record
- **Investigation Reports** — Generate formal PDF investigation reports for flagged trips
- **Microsoft Azure AD Login** — MSAL-based SSO authentication
- **Audit Log** — Tamper-evident, timestamped record of all significant user actions
- **Admin Panel** — User management and system configuration

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 SPA (single HTML file, compiled bundle) |
| Backend | Python · Flask · SQLite |
| Auth | Microsoft Azure AD (MSAL Browser) |
| Email | EmailJS |
| Forms | Zoho Forms |
| Charts | Canvas 2D API |
| Styles | CSS custom properties (dark theme) |

---

## Project Structure

```
FAS/
├── FuelVarianceAudit_6.html       # Main SPA (React app + all extensions)
├── FuelVarianceAudit_Login.html   # Login page (Azure AD / PIN fallback)
├── FuelVarianceAudit_Server.py    # Flask backend (auth, API endpoints)
├── FuelVarianceAudit_DB.sql       # Database schema
├── requirements.txt               # Python dependencies
├── emailjs-4.min.js               # EmailJS browser SDK
├── msal-browser.min.js            # Microsoft MSAL browser SDK
├── fva-logo.png                   # App logo
├── zoho-auth-server.js            # Zoho OAuth helper (Node)
└── zoho-proxy.js                  # Zoho API proxy (Node)
```

---

## Setup

### Prerequisites

- Python 3.9+
- A registered Azure AD application (for SSO login)
- EmailJS account with a configured template
- Zoho Forms account (for driver statement form)

### Backend

```bash
pip install -r requirements.txt
python FuelVarianceAudit_Server.py
```

The server runs on `http://localhost:5000` by default.

### Frontend

Open `FuelVarianceAudit_Login.html` in a browser (served via the Flask server or any static file host).

### Environment / Secrets

The following files are **not tracked in git** and must be configured locally:

| File | Purpose |
|------|---------|
| `.fva_secret` | Flask secret key and JWT signing secret |
| `.fva_zoho_config` | Zoho OAuth client ID, secret, and form URL |
| `self_client.json` | Zoho self-client OAuth credentials |

---

## PIN Roles (development / fallback)

When Azure AD login is unavailable, a PIN entry screen is shown:

| PIN | Role |
|-----|------|
| 2468 | Administrator |
| 3579 | Dispatch |
| 4680 | Exco |
| 7531 | Head of Dept |

---

## License

Internal use only — Skybridge (Pty) Ltd. Not for public distribution.
