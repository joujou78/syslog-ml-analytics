# Syslog ML Analytics — Frontend

React + TypeScript + Vite. See `../README.md` for architecture, local
dev setup, and production deployment (nginx + the FastAPI backend).

Quick reference:

```bash
npm install
npm run dev        # dev server on :5173, proxies /api to :8000
npm run build      # production build -> dist/
npm run test:e2e   # Playwright smoke test (needs both servers running)
```
