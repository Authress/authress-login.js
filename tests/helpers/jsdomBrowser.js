/**
 * Helpers for tests running in the vitest jsdom environment, whose `document.cookie` is backed by a standards compliant cookie jar, so tests observe what a browser actually stores and returns.
 */
export const browseTo = url => globalThis.jsdom.reconfigure({ url });

export const storedCookie = async cookieName => (await globalThis.jsdom.cookieJar.getCookies(window.location.href)).find(cookie => cookie.key === cookieName);

export const serverSetsCookie = (setCookieHeader, responseUrl) => globalThis.jsdom.cookieJar.setCookie(setCookieHeader, responseUrl);

export async function clearBrowserState() {
  await globalThis.jsdom.cookieJar.removeAllCookies();
  localStorage.clear();
}
