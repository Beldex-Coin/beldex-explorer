# Beldex Explorer — React frontend

Full design revamp of the explorer UI in React (Vite), styled after beldex.io:
near-black dot-grid canvas, Michroma display type, Space Mono body, sharp white
buttons, Beldex green (#00d959) accents.

## Develop

```sh
cd frontend
npm install
npm run dev
```

The dev server proxies `/api/*` to the Flask explorer at `http://127.0.0.1:5000`
(override with `VITE_API_TARGET`). If the API is unreachable in dev, the UI
falls back to built-in mock data so every page stays previewable. Force mock
mode with `VITE_USE_MOCK=1 npm run dev`.

## Build

```sh
npm run build   # outputs to frontend/dist
```

Serve `dist/` behind the same origin as the Flask app (or set `VITE_API_BASE`),
with all non-`/api` routes falling back to `index.html`.

## Backend

The SPA consumes the JSON endpoints added at the bottom of `../explorer.py`
(`/api/v2/summary`, `/blocks`, `/block/<id>`, `/tx/<txid>`, `/mempool`,
`/master_nodes`, `/mn/<pubkey>`, `/quorums`, `/search`, `/tokens`) plus the
existing `/api/bnslookup`.
