# Change log
This is the changelog for [Authress Login](readme.md).

## 1.1 ##
* Added `authorization-code` exchange specifying necessary parameters `responseMode = query` and `responseType = code`.
* Calling `authenticate` no longer redirects user to the `redirectUrl` if the user is already logged in. Redirects will still happen for users not logged in. This fixes a problem where the mechanism for redirects did not match the framework redirect mechanism. In some cases causing refresh loops.
