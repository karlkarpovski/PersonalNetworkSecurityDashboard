import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: Number(process.env.PNS_UI_PORT ?? 5173),
    strictPort: true,
    cors: false,
    proxy: {
      '/api/': { target: `http://127.0.0.1:${Number(process.env.PNS_API_PORT ?? 5181)}`, changeOrigin: true, ws: true },
    },
  },
});
