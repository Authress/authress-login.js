import { describe, it, afterEach, expect, vi } from 'vitest';

import { LoginClient } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('loginClient.js', () => {
  describe('userSessionExists', () => {
    it('Calls through to user session continuation.', async () => {
      const loginClient = new LoginClient({ authenticationServiceUrl: 'https://unit-test.authress.io', applicationId: 'app_default', skipBackgroundCredentialsCheck: true });
      const userSessionContinuationSpy = vi.spyOn(loginClient, 'userSessionContinuation');
      userSessionContinuationSpy.mockImplementationOnce(() => Promise.resolve(true));

      const result = await loginClient.userSessionExists({ backgroundTrigger: false });
      expect(userSessionContinuationSpy).toHaveBeenCalledTimes(1);
      expect(userSessionContinuationSpy).toHaveBeenCalledWith(false);
      expect(result).toEqual(true);
    });
  });

  describe('userSessionExists', () => {
    it('Partial user cookie works as intended.', async () => {
      const loginClient = new LoginClient({ authenticationServiceUrl: 'https://security.standup-and-prosper.com', applicationId: 'app_cGTmT53Ez2nhg41dtKTE9b', skipBackgroundCredentialsCheck: true });

      const cookies = {
        authorization: 'eyJpc3MiOiJodHRwczovL3NsYWNrLXRva2VuLXRlc3QuYXV0aHJlc3MuaW8iLCJzdWIiOiJzbGFja3xUMzA0MUJDMVp8VTMwNjFVWjhBIiwiaWF0IjoxNzU4NjQwNTI4LCJleHAiOjE3NTg3MjY5MjgsImp0aSI6InNsYWNrfFQzMDQxQkMxWnxVMzA2MVVaOEEtMjM5YTY5NDAtOTg5MC0xMWYwLWIzNjktM2ZkNjhlMjYxMTE5fHZYYndQZjN2cy1YQ0ZrOGFod01DSHFCYk1JVnRDR0VnVXNxUjQyZk01SXF4ZHNQdEhRYmlDcjlMMnZYQWlVVDhTVVd1SGNUWlVWY3hSY01tTUU0UmZRIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFhaWwiLCJhenAiOiJjb25fajFtVlFUcHp1b3VOSDN2V3hKRFp5QiIsImNsaWVudF9pZCI6ImFwcF9jR1RtNTNFejJuaGc0MWR0S1RFOWIiLCJhdWQiOlsiQURaTUNHTkowIl19.<sig>',
        user: '.eyJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZGF0YSI6eyJzdWIiOiJVMzA2MVVaOEEiLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2ltYWdlX2RlZmF1bHQiOmZhbHNlLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2lkIjoiVDMwNDFCQzFaIiwibG9jYWxlIjoiZW4tVVMiLCJkYXRlX2VtYWlsX3ZlcmlmaWVkIjoxNjMzOTczMDYyLCJodHRwczovL3NsYWNrLmNvbS91c2VyX2lkIjoiVTMwNjFVWjhBIiwib2siOnRydWUsImVtYWlsIjoiRU1BSUwiLCJodHRwczovL3NsYWNrLmNvbS90ZWFtX2RvbWFpbiI6IkRPTUFJTiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfSwibmFtZSI6IlRFU1QtTkFNRSIsImNvbnRleHQiOnsib2siOnRydWV9LCJsb2NhbGUiOiJlbi1VUyIsImZhbWlseV9uYW1lIjoiIiwicGljdHVyZSI6Imh0dHBzOi8vc2VjdXJlLmdyYXZhdGFyLmNvbS9hdmF0YXIvODgzM2ZjMmFiZTViMjNkNjk4NjY3YzdhZTAwNDY2NjcuanBnP3M9NTEyJmQ9aHR0cHMlM0ElMkYlMkZhLnNsYWNrLWVkZ2UuY29tJTJGZGYxMGQlMkZpbWclMkZhdmF0YXJzJTJGYXZhXzAwMjUtNTEyLnBuZyIsInN1YiI6InNsYWNrfFQzMDQxQkMxWnxVMzA2MVVaOEEiLCJpYXQiOjE3NTg2NDA1MjgsImV4cCI6MTc1ODcyNjkyOCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9'
      };
      
      const getDocumentSpy = vi.spyOn(windowManager, 'getDocument').mockImplementation(() => ({
        cookie: Object.keys(cookies).map(k => `${k}=${cookies[k]}`).join('; ')
      }));

      const result = await loginClient.userSessionContinuation(false);
      expect(getDocumentSpy).toHaveBeenCalled();
      expect(result).toEqual(true);
    });
  });
});
