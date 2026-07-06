import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Builds the contact form React island into a single self-mounting IIFE file
// at assets/contact-widget/contact-widget.js, which the static contact.html
// loads with a plain <script> tag. React + ReactDOM are bundled in, so there
// are no runtime CDN dependencies.
export default defineConfig({
  plugins: [react()],
  define: {
    // Force React's production build (smaller, no dev warnings).
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  build: {
    outDir: 'assets/contact-widget',
    emptyOutDir: true,
    cssCodeSplit: false,
    lib: {
      entry: 'src/contact/main.jsx',
      name: 'MSMEContactWidget',
      formats: ['iife'],
      fileName: () => 'contact-widget.js',
    },
    rollupOptions: {
      output: {
        assetFileNames: 'contact-widget.[ext]',
      },
    },
  },
});
