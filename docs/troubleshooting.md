# Troubleshooting usage

## esbuild fails to build due to Buffer
There are some modules used by Authress Login which require polyfills for the browser. Some bundlers such as Rollup and Webpack pull these in automatically, under certain cases. Others do not. If you run into an issue, make sure to check the documentation.

For esbuild build script, a quick change to the build configuration solves this:

```sh
npm i @esbuild-plugins/node-globals-polyfill

```

#### ESBuild:
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
```js
optimizeDeps: {
  esbuildOptions: {
    define: { global: 'globalThis' },
    plugins: [
      NodeGlobalsPolyfillPlugin({
        buffer: true
      })
    ]
  }
}
```
