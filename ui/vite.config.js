import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://localhost:9090' } },
  build: {
    rollupOptions: {
      input: { landing: resolve(__dirname, 'index.html'), app: resolve(__dirname, 'app.html') },
    },
  },
})
