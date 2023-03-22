const cookieManager = require('cookie');

const AuthenticationCredentialsStorageKey = 'AuthenticationCredentialsStorage';

class UserIdentityTokenStorageManager {
  set(value, expiry) {
    try {
      const cookies = cookieManager.parse(document.cookie);
      localStorage.setItem(AuthenticationCredentialsStorageKey, JSON.stringify({ idToken: value, expiry: expiry && expiry.getTime(), jsCookies: !!cookies.authorization }));
      this.clearCookies('user');
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  get() {
    try {
      const { idToken, expiry, jsCookies } = JSON.parse(localStorage.getItem(AuthenticationCredentialsStorageKey) || '{}');
      if (!idToken || expiry < Date.now()) {
        return null;
      }

      const cookies = cookieManager.parse(document.cookie);
      // If the authorization cookie was present when the identity was stored, then it must still be present after, otherwise we know that the user data saved isn't valid anymore
      // * If the authorization cookie wasn't present, then it is because the application configuration restricts access to javascript.
      // * That means that the implementation can't use the presence of the ID token information to make a decision about if the user is logged in.
      if (jsCookies && !cookies.authorization) {
        return null;
      }

      return idToken;
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
      return null;
    }
  }

  delete() {
    try {
      localStorage.removeItem(AuthenticationCredentialsStorageKey);
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  clear() {
    this.clearCookies();
    this.delete();
  }

  clearCookies(cookieName) {
    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
      // Remove only the cookies that are relevant to the client
      if (!['user', 'authorization', 'auth-code'].includes(cookie.split('=')[0]) || cookieName && cookie.split('=')[0] !== cookieName) {
        continue;
      }
      const domain = window.location.hostname.split('.');
      while (domain.length > 0) {
        const cookieBase = `${encodeURIComponent(cookie.split(';')[0].split('=')[0])}=; expires=Thu, 01-Jan-1970 00:00:01 GMT; domain=${domain.join('.')} ;path=: SameSite=Strict`;
        const path = location.pathname.split('/');
        document.cookie = `${cookieBase}/`;
        while (path.length > 0) {
          document.cookie = cookieBase + path.join('/');
          path.pop();
        }
        domain.shift();
      }
    }
  }
}

module.exports = new UserIdentityTokenStorageManager();
