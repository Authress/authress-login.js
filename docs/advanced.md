## Advanced method documentation

### [`userSessionExists()`](https://github.com/Authress/authress-login.js/blob/release/2.3/src/index.js#L241)

This method is the primary check to ensure that the current user is logged in. As detailed it should be called every time the user enters a part of the app in which they need to be logged in. Usually it should be called as part of the router route guard for these routes with API calls. In the case that the user is logged in already no extra calls are made to Authress which means 99% of the time this is an in memory/browser check for the user.

In any case--irrespective of the data stored in the browser, cache, or in Authress--this method returns `true` if `authorization` and `user` tokens can be secured for the user. In most cases these tokens end up in the user's secure `same-site` cookies. In the case that the method `returns false`, instead of routing the user to the page, route the user to a login page which contains a call the `loginClient.authenticate()` method (as seen below).

`userSessionExists()` has different logic depending on where it is being run (i.e. localhost versus production domain). I'll assume we are talking about production for a second. And by production is important that we mean a domain that matches your custom domain `app.example.com` if `login.example.com` is your [Authress Custom Domain](https://authress.io/app/#/setup?focus=domain).

It will return `true`, if:
* We've set the flow to be `code`, and there is a valid code, this isn't common, and would have to be explicitly configured as part of the last made `authenticate(options)` call.
* If the Authress `user` cookie for your app is set and not expired (We don't use the `authorization` cookie, because it is possible to prevent cookie access to js, by setting the `HttpOnly cookie flag` in the application configuration)
* OR, The user has an active session (verified by a number of different things), in which case new `authorization` and new `user` cookies are set.

### [`ensureToken()`](https://github.com/Authress/authress-login.js/blob/release/2.3/src/index.js#L585)
Actually attempts to fetch the token from the `authorization` cookie and if it doesn't exists returns `null`, but it doesn't change any state. You can call this all day long and it will never redirect the user anywhere. Since calling this doesn't change state, it doesn't have any impact on your application. If you experience a state change, it is possible that the browser blocked a request, to `/session` or `authorization` preventing a check to Authress to start the login or continue an existing session.

### [`authenticate(options)`](https://github.com/Authress/authress-login.js/blob/release/2.3/src/index.js#L525)
Validates that the user does not have an available session and then redirects to the user via the configured options to the Authress Login screen to actually log in. The result of this call will be the user ending up back in your app, at the specified redirect location. At that time **repeat the call to the `userSessionExists()` method above**. It is important as always to call `userSessionExists()` as soon as possible so that any login flow that might be in-progress gets completed.

### [`updateExtensionAuthenticationRequest(options)`](https://github.com/Authress/authress-login.js/blob/release/2.3/src/index.js#L371)
Works the same as `authenticate`, but expects to be called as part of the login flow for users coming from an extension login. Pass the expected parameters, and the user will be logged and redirected to the appropriate extension post login page.

### [`openUserConfigurationScreen(options)`](https://github.com/Authress/authress-login.js/blob/release/2.3/src/index.js#L158)
Navigate the user to the profile screen to configure their MFA options. A common usage is `await loginClient.openUserConfigurationScreen({ startPage: UserConfigurationScreen.MFA })
