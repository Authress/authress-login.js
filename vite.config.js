import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { babel } from '@rollup/plugin-babel';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageMetadata = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8'));
const version = packageMetadata.version.replace(/"/g, '');

const banner = `
/**
* @preserve
* Authress Login SDK ${version}
* License: Apache-2.0
* Repo   : https://github.com/Authress/login-sdk.js
* Author : Authress Developers
*/`;

const babelConfig = {
  presets: [
    [
      "@babel/preset-env",
      {
        "targets": {
          "esmodules": true,
          "android": "80",
          "chrome": "85",
          "edge": "87",
          "firefox": "84",
          "ios": "13",
          "node": "14",
          "opera": "72",
          "safari": "14",
          "samsung": "14"
        },
        "bugfixes": true
      }
    ]
  ]
};

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src')
    }
  },

  server: {
    port: 8080
  },
  build: {
    targets: 'esnext',
    outDir: path.join(__dirname, 'dist'),
    sourcemap: true, 
    minify: 'terser',
    terserOptions: {
      format: {
        comments: (node, comment) => /^\**!|@preserve|@license|@cc_on/i.test(comment.value),
      },
    },
    
    lib: {
      entry: path.resolve(__dirname, 'src/index.js'),
      name: 'Authress',
      formats: ['umd'],
      fileName: () => 'authress.min.js'
    },

    rollupOptions: {
      plugins: [
        babel({
          exclude: 'node_modules/**', 
          babelHelpers: 'bundled',
          presets: [
            [
              "@babel/preset-env",
              {
                bugfixes: true,
                browserslistEnv: "production"
              }
            ]
          ]
        }),
        {
          name: 'banner',
          renderChunk(code) {
            return banner + '\n' + code;
          }
        },
      ],

      output: {
        chunkFileNames: 'chunks/[name]-[hash].js',
        exports: 'named',
        footer: `
          /* License information can be found at https://github.com/Authress/login-sdk.js */
        `
      }
    }
  }
});