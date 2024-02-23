module.exports.sanitizeUrl = function sanitizeUrl(rawUrlStrng) {
  let sanitizedUrl = rawUrlStrng;
  if (!sanitizedUrl.startsWith('http')) {
    sanitizedUrl = `https://${sanitizedUrl}`;
  }

  const url = new URL(sanitizedUrl);
  const domainBaseUrlMatch = url.host.match(/^([a-z0-9-]+)[.][a-z0-9-]+[.]authress[.]io$/);
  if (domainBaseUrlMatch) {
    url.host = `${domainBaseUrlMatch[1]}.login.authress.io`;
    sanitizedUrl = url.toString();
  }

  return sanitizedUrl.replace(/[/]+$/, '');
};
