# Troubleshooting usage

## Why do I get a timeout when calling `ensureToken`

`ensureToken` attempts to wait for a token to be available. It attempts to block code execution until one is. The reason for this is that `useSessionExists` and `authenticate` might be called in a separate thread or a separate browser tab. When this happens multiple user actions or site code flows might result in many API requests to your backend all depending on `ensureToken`. Without the block, all these requests would be sent without a token (worst case) or throw an error everywhere in your code based (better case).

When a user session exists but the token is expired, instead we use the session to generate a new token. To prevent the race condition and causing the API requests that depend on a valid token from throwing error, `ensureToken` blocks (best case)

But what if there is no session, and the user must log in?

In the past `ensureToken` blocked forever, however this can create an unexpected situation in your site where the code "gets stuck", because methods that do that are often unexpected in libraries. So instead we enable a timeout for when you feel how long it is reasonable to wait for a token. The default timeout is set to be 5 seconds.

`ensureToken` seeks to never return `null`, as that can create a `pit of failure`, instead it throws.

The recommended flow for interacting with the login SDK could be instead something like this in one place in your whole site:
```js
const loggedIn = await client.userSessionExists();
if (!loggedIn) {
  await client.authenticate();
  return;
}

// And then everywhere else you need a token:
(Example Code Location: Site 1)
const token = await client.ensureToken();
```

Additionally worth mentioning is that `ensureToken` actually already calls userSessionExists. So code like this is never necessary:
```js
const loggedIn = await client.userSessionExists()
if (loggedIn) {
  const token = await client.ensureToken({})
  // Use token
}
```

And instead can be simplified to be:

(Example Code Location: Site 1)
```js
try {
  const token = await client.ensureToken();
  // Use token
} catch (error) {
  // Do something else
}
```

Additionally, it is important to note that this @authress/login library already handles all the necessary token state management. If you have places in your code based that include `setSessionToken` and somewhere else with `getSessionToken` (For example in a Site 2 location, called site 1 and site 2 to indicate these are in the code based in very different locations), instead, delete all the "site 1" code and then at "site 2" where you are presumably where `getSessionToken` was being called, directly call into the library with `const token = await client.ensureToken()`.

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
