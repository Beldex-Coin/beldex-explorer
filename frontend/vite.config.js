import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev proxy: forward API calls to the Flask explorer (default :5000).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:5000',
        changeOrigin: true,
      },
    },
  },
})
