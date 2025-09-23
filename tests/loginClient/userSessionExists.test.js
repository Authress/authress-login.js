const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../../src/index');
const windowManager = require('../../src/windowManager');
const userIdentityTokenStorageManager = require('../../src/userIdentityTokenStorageManager.js');

let sandbox;
beforeEach(() => { sandbox = sinon.createSandbox(); });
afterEach(() => sandbox.restore());

describe('loginClient.js', () => {
  describe('userSessionExists', () => {
    it('Calls through to user session continuation.', async () => {
      const loginClient = new LoginClient({ authenticationServiceUrl: 'https://unit-test.authress.io', applicationId: 'app_default', skipBackgroundCredentialsCheck: true });

      const loginClientMock = sandbox.mock(loginClient);
      loginClientMock.expects('userSessionContinuation').once().withExactArgs(false).resolves(true);

      const result = await loginClient.userSessionExists({ backgroundTrigger: false });

      loginClientMock.verify();

      expect(result).to.eql(true);
    });
  });

  describe('userSessionExists', () => {
    it('Partial user cookie works as intended.', async () => {
      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);

      const loginClient = new LoginClient({ authenticationServiceUrl: 'https://security.standup-and-prosper.com', applicationId: 'app_cGTmT53Ez2nhg41dtKTE9b', skipBackgroundCredentialsCheck: true });
      const loginClientMock = sandbox.mock(loginClient);

      const cookies = {
        authorization: 'eyJpc3MiOiJodHRwczovL3NsYWNrLXRva2VuLXRlc3QuYXV0aHJlc3MuaW8iLCJzdWIiOiJzbGFja3xUMzA0MUJDMVp8VTMwNjFVWjhBIiwiaWF0IjoxNzU4NjQwNTI4LCJleHAiOjE3NTg3MjY5MjgsImp0aSI6InNsYWNrfFQzMDQxQkMxWnxVMzA2MVVaOEEtMjM5YTY5NDAtOTg5MC0xMWYwLWIzNjktM2ZkNjhlMjYxMTE5fHZYYndQZjN2cy1YQ0ZrOGFod01DSHFCYk1JVnRDR0VnVXNxUjQyZk01SXF4ZHNQdEhRYmlDcjlMMnZYQWlVVDhTVVd1SGNUWlVWY3hSY01tTUU0UmZRIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImF6cCI6ImNvbl9qMW1WUVRwenVvdU5IM3ZXeEpEellCIiwiY2xpZW50X2lkIjoiYXBwX2NHVG1UNTNFejJuaGc0MWR0S1RFOWIiLCJhdWQiOlsiQURaTUNHTkowIl19.<sig>',
        user: '.eyJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZGF0YSI6eyJzdWIiOiJVMzA2MVVaOEEiLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2ltYWdlX2RlZmF1bHQiOmZhbHNlLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2lkIjoiVDMwNDFCQzFaIiwibG9jYWxlIjoiZW4tVVMiLCJkYXRlX2VtYWlsX3ZlcmlmaWVkIjoxNjMzOTczMDYyLCJodHRwczovL3NsYWNrLmNvbS91c2VyX2lkIjoiVTMwNjFVWjhBIiwib2siOnRydWUsImVtYWlsIjoiRU1BSUwiLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2RvbWFpbiI6IkRPTUFJTiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfSwibmFtZSI6IlRFU1QtTkFNRSIsImNvbnRleHQiOnsib2siOnRydWV9LCJsb2NhbGUiOiJlbi1VUyIsImZhbWlseV9uYW1lIjoiIiwicGljdHVyZSI6Imh0dHBzOi8vc2VjdXJlLmdyYXZhdGFyLmNvbS9hdmF0YXIvODgzM2ZjMmFiZTViMjNkNjk4NjY3YzdhZTAwNDY2NjcuanBnP3M9NTEyJmQ9aHR0cHMlM0ElMkYlMkZhLnNsYWNrLWVkZ2UuY29tJTJGZGYxMGQlMkZpbWclMkZhdmF0YXJzJTJGYXZhXzAwMjUtNTEyLnBuZyIsInN1YiI6InNsYWNrfFQzMDQxQkMxWnxVMzA2MVVaOEEiLCJpYXQiOjE3NTg2NDA1MjgsImV4cCI6MTc1ODcyNjkyOCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9'
      };
      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('getDocument').atLeast(1).returns({ cookie: Object.keys(cookies).map(k => `${k}=${cookies[k]}`).join('; ') });
      const result = await loginClient.userSessionContinuation(false);

      loginClientMock.verify();
      userIdentityTokenStorageManagerMock.verify();
      windowManagerMock.verify();

      expect(result).to.eql(true);
    });
  });
});

