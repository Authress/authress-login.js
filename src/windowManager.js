class WindowManager {
  onLoad(callback) {
    if (typeof window !== 'undefined') {
      window.onload = callback;
    }
  }

  isLocalHost() {
    const isLocalHost = typeof window !== 'undefined' && window.location && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
    return isLocalHost;
  }

  getCurrentLocation() {
    return typeof window !== 'undefined' && new URL(window.location) || new URL('http://localhost:8080');
  }

  getDocument() {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return null;
    }
    return document;
  }

  assign(newLocationUrl) {
    if (typeof window === 'undefined') {
      return null;
    }
    return window.location.assign(newLocationUrl.toString());
  }

  open(newLocationUrl) {
    if (typeof window === 'undefined') {
      return null;
    }
    return window.open(newLocationUrl.toString());
  }
}

module.exports = new WindowManager();
