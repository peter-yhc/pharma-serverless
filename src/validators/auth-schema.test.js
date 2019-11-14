const { signupSchema } = require('./auth-schemas');

describe('test authentication payload schemas', () => {
  describe('for all signup schemas', () => {
    test('can validate username', () => {
      const { error } = signupSchema.validate({
        username: 1,
        password: 'correct',
        repeat_password: 'correct',
        email: 'valid@valid.com',
      });
      expect(error.message).toBe('"username" must be a string');
    });

    test('can validate username', () => {
      const { error } = signupSchema.validate({
        username: '21',
        password: 'correct',
        repeat_password: 'correct',
        email: 'valid@valid.com',
      });
      expect(error.message).toBe('"username" must be a string');
    });
  });
});
