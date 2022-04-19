# Troubleshooting usage

## Buffer is not defined (esbuild/vite)
There are some modules used by Authress Login which require polyfills for the browser. Some bundlers such as Rollup and Webpack pull these in automatically, under certain cases. Others do not. If you run into an issue, make sure to check the documentation.

For esbuild build script, a quick change to the build configuration solves this:

#### ESBuild:
```sh
npm i @esbuild-plugins/node-globals-polyfill
```

```js
import GlobalsPolyfills from '@esbuild-plugins/node-globals-polyfill';
await esbuild
  .build({
    define: { global: "window" },
    plugins: [
      GlobalsPolyfills({
        buffer: true
      })
    ]
  })
```

#### vite.config.js:
```sh
npm i @esbuild-plugins/node-globals-polyfill rollup-plugin-polyfill-node
```

```js
import RollupNodePolyFill from 'rollup-plugin-polyfill-node';
import NodeGlobalsPolyfillPlugin from '@esbuild-plugins/node-globals-polyfill';

export default defineConfig({
  build: {
    rollupOptions: {
      plugins: [
        RollupNodePolyFill()
      ]
    }
  },
  optimizeDeps: {
    esbuildOptions: {
      define: {
        global: 'globalThis'
      },
      plugins: [
        NodeGlobalsPolyfillPlugin({ buffer: true })
      ]
    }
  },
})
```
