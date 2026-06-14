import { defineConfig } from 'vite';

export default defineConfig({
  // Relative base so assets resolve correctly when Capacitor loads from file://
  base: './',
  build: {
    outDir: 'dist',
    target: 'es2017',
  },
});
