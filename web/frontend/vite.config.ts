import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Backend runs on :8000 in dev; proxying avoids needing CORS config
      // changes every time the frontend origin/port changes.
      '/api': 'http://localhost:8000',
    },
  },
})
