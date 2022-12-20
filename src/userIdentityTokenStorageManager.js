const AuthenticationCredentialsStorageKey = 'AuthenticationCredentialsStorage';

class UserIdentityTokenStorageManager {
  set(value, expiry) {
    try {
      localStorage.setItem(AuthenticationCredentialsStorageKey, JSON.stringify({ idToken: value, expiry: expiry && expiry.getTime() }));
      this.clearCookies('user');
    } catch (error) {
      console.debug('LocalStorage failed in Browser', error);
    }
  }

  get() {
    try {
      const { idToken, expiry } = JSON.parse(localStorage.getItem(AuthenticationCredentialsStorageKey) || '{}');
      if (!idToken || expiry < Date.now()) {
        localStorage.removeItem(AuthenticationCredentialsStorageKey);
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

  clearCookies(cookieName) {
    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
      // Remove only the cookies that are relevant to the client
      if (!['user', 'authorization', 'auth-code'].includes(cookie.split('=')[0]) || cookieName && cookie.split('=')[0] !== cookieName) {
        continue;
      }
      const domain = window.location.hostname.split('.');
      while (domain.length > 0) {
        const cookieBase = `${encodeURIComponent(cookie.split(';')[0].split('=')[0])}=; expires=Thu, 01-Jan-1970 00:00:01 GMT; domain=${domain.join('.')} ;path=`;
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
