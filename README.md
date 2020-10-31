# authress-login
The Authress Universal Login SDK for javascript app websites and service authentication. Used to integrate with the authentication as a service provider Authress at https://authress.io.


[![npm version](https://badge.fury.io/js/authress-login.svg)](https://badge.fury.io/js/authress-login)


## Usage

```sh
npm install authress-login
```

Then required the package:
```js
const { LoginClient } = require('authress-login');
```

## Getting Started

### Part 0: Setup Authress Login
You'll want to create:
* at least one provider connection - https://authress.io/app/#/manage?focus=connections
* an application which represents your web app - https://authress.io/app/#/manage?focus=applications

### Part 1: Web App UI

On every route change check to see if the user exists, and if they don't redirect them to a login prompt.
```js
// Both of these properties an be found and configured at: https://authress.io/app/#/manage?focus=applications
const loginClient = new LoginClient({ authenticationServiceUrl: 'https://login.application.com', applicationId: 'YOUR_APPLICATION_ID' });
const isUserLoggedIn = await loginClient.userSessionExists();
if (!isUserLoggedIn) {
  window.location.assign('/login');
}
```
In your app's login screen when the user selects how they would like to login, direct them there. And also specify where you would like Authress to redirect the user to after login. By default this is the user's current location.
```js
await loginClient.authenticate({ connectionId: 'SELECTED_CONNECTION_ID', redirectUrl: window.location.href });
return;
```

When API calls are made your services that are hosted on the same domain `api.application.com`, `other-app.application.com` a cookie will automatically sent. If you wish to interact with an insecure other domain, you can use:
```js
const userToken = await loginClient.getToken();
```

### Part 2: User Authentication in Service APIs

On the service API side, the recommendation is to pull in the Authress service client library. Which is a companion for this one. `npm install authress-sdk`, alternatively you can grab the user auth cookie directly.

* First install `npm install authress-sdk`
* Then verify the incoming tokens:

```js
const { TokenVerifier } = require('authress-sdk');
const cookieManager = require('cookie');

try {
  // Grab authorization cookie from the request, the best way to do this will be framework specific.
  const cookies = cookieManager.parse(request.headers.cookie || '');
  const userToken = cookies.authorization;
  // Specify your custom domain for tokens. Configurable at https://authress.io/app/#/manage?focus=applications
  const userIdentity = await TokenVerifier('https://login.application.com', cookies.authorization);
} catch (error) {
  console.log('User is unauthorized', error);
  return { statusCode: 401 };
}
```
