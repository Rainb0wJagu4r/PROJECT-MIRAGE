import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

const hasCerts = fs.existsSync('./certs/localhost.pem') && fs.existsSync('./certs/localhost-key.pem');

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: hasCerts ? 'https://localhost:3001' : 'http://localhost:3001',
        changeOrigin: true,
        secure: false,
      }
    }
  }
})
