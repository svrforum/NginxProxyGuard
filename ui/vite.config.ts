import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split heavy third-party deps into their own chunks so they aren't
        // inlined into every route bundle. Browsers can fetch these in
        // parallel and reuse them across pages via the HTTP cache, cutting
        // both the first-load and route-switch payload. Function form is
        // required by Rolldown (Vite 8's bundler) — the object shorthand
        // accepted by classic Rollup is not supported.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          if (/[\\/]node_modules[\\/]recharts[\\/]/.test(id)) return 'recharts'
          if (/[\\/]node_modules[\\/](react-simple-maps|topojson-client|d3-)/.test(id)) return 'maps'
          if (/[\\/]node_modules[\\/](react-datepicker|date-fns)[\\/]/.test(id)) return 'datepicker'
          if (/[\\/]node_modules[\\/](i18next|react-i18next)/.test(id)) return 'i18n'
          if (/[\\/]node_modules[\\/]@tanstack[\\/]react-query[\\/]/.test(id)) return 'query'
          if (/[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/.test(id)) return 'react-vendor'
          return undefined
        },
      },
    },
  },
})
