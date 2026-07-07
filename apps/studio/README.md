# Mythos Studio

Local Electron launcher for Mythos Studio.

It starts the local FastAPI backend and the local Next.js Studio surface, waits
until the Studio URL is ready, and then opens `/studio` in a desktop window. If
the local service does not become ready, the app shows a local startup error
page instead of a blank window.

The launcher prefers API port `8000` and Web port `3000`, but it automatically
uses the next available local ports when either one is already occupied. Set
`MYTHOS_API_PORT` or `MYTHOS_WEB_PORT` only when you need fixed local ports.

## Setup

```powershell
cd apps/api
python -m pip install -r requirements.txt
cd ../web
npm install
cd ../studio
npm install
npm start
```

## Verification

```powershell
npm test
```

## Safety

This launcher does not enable public-target attacks, destructive validation, real-user-data handling, raw secret storage, or automatic report submission.
