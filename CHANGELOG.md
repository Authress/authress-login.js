# Change log
This is the changelog for [Authress Login](readme.md).

## 2.5 ##
* Handle `<HTML DOCUMENT></HTML>` improved with better error investigation into the `error.data` property as well.
* Also remove the `AuthUserId` cookie when removing other cookies.
* Add `antiAbuseHash` generation as part of authentication requests
* clear the `nonce` and `iss` parameters from the URL when they are set.

## 2.4 ##
* Prevent silent returns from `authenticate` when a different connectionId is used to have the user log in.
* Throw error on invalid application specified from inside the SDK for improved debugging.
* Support returning the `authenticationUrl` via the `authenticate` response for implementations that don't require a redirect.

## 2.3 ##
* Add MFA device methods.
* Improve http error handling when there is an issue authenticating.
* Reduce logging level for SESSION continuation.
* Temporarily remove encouragement for generating non-256 backed webauthn keys as some browsers don't support more complex options.
* Support missing TOTP saving of devices.

## 2.2 ##
* Automatically retry on network connection issues.
* Handle expired requests on code exchanges.
* Fallback to user cookie when LocalStorage is blocked for user.
* Support removing of the cookies set at the current domain, not just subdomain cookies. This change fixes an bug in the intended version 2.0 function, if you are expecting the `user` cookie to be stored, and it is no longer available, this change is the reason. Direct dependency on the Authress cookies should never be used, all functionality is exposed through this SDK, as implementation of hidden login interface is not stable. This library is stable, so only the published interface is supposed.
* Add missing `inviteId` to the `authenticate` api.

## 2.1 ##
* Remove `connectionId` and `tenantLookupIdentifier` requirements from the authentication call so that the user can be directed to the Authress Hosted login when necessary: https://authress.io/app/#/settings?focus=branding
* Enable the methods to have optional inputs parameters when not required
* Automatically handle replay attacks against the user by ignoring the request and opting for returning no token. (Error('InvalidNonce') will no longer be thrown.)
* Enable explicit SameSite=Strict

## 2.0 ##
* Optimize cookie storage location for the `user` cookie.
* Use more secure `PATCH` for session management.
* Remove deprecated properties from previous version.
* Increase time span for duplicate session checks to 50ms
* Add automatic retries to network connection issues.
* Add AuthUserId cookie available in all requests to replace the `user` cookie.
* Avoid unnecessary CORS warnings when using a cross domain application
* Improve logout redirect url default location

## 1.4 ##
* Include the extensionClient as embeddable client for OAuth extension login.
* Add `linkIdentity` parameter to Authenticate and `unlinkIdentity` method to support account linking.

## 1.3 ##
* Automatically trigger credentials checking on load.
* Support 127.0.0.1 for localhost
* Add the `updateExtensionAuthenticationRequest` method to support handling platform extension login.

## 1.2 ##
* Use builtin `crypto.subtle` for all crypto operations.
* Publish a babel to work with vanilla.js.

## 1.1 ##
* Added `authorization-code` exchange specifying necessary parameters `responseMode = query` and `responseType = code`.
* Calling `authenticate` no longer redirects user to the `redirectUrl` if the user is already logged in. Redirects will still happen for users not logged in. This fixes a problem where the mechanism for redirects did not match the framework redirect mechanism. In some cases causing refresh loops.
* Return the full OIDC identity when calling `getUserData()` instead of only a limited set.
* Add `tenantLookupIdentifier` property to `authenticate` to specify a specific tenant to use rather than just the `connection`.
* Support `connectionProperties` in `authenticate` to override connection and identity provider specific defaults.
* `logout` redirects the user client to the hosted login UI to ensure logout happens, and then is redirected back.
* Add `UserCredentials` and `getConnectionCredentials` to fetch the credentials associated with the connected provider.
* Deprecate `getUserData` in favor of `getUserIdentity`
