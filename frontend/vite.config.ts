/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Backend is localhost-only, plain HTTP, cookie-session auth (see
    // backend/app/auth.py). Proxying same-origin avoids CORS/cookie
    // cross-origin headaches entirely instead of adding CORS middleware.
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/setupTests.ts'],
    pool: 'threads',
  },
})
