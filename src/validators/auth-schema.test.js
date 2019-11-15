const { signupSchema } = require('./auth-schemas');

describe('test authentication payload schemas', () => {
  describe('for all signup schemas', () => {
    test('can validate username bad format', () => {
      const { error } = signupSchema.validate({
        username: 1,
        password: 'correct',
        repeatPassword: 'correct',
        email: 'valid@valid.com',
      });
      expect(error.message).toBe('"username" must be a string');
    });

    test('can validate username bad length - min', () => {
      const { error } = signupSchema.validate({
        username: '21',
        password: 'correct',
        repeatPassword: 'correct',
        email: 'valid@valid.com',
      });
      expect(error.message).toContain('username');
      expect(error.message).toContain('at least 3');
    });

    test('can validate username bad length - max', () => {
      const { error } = signupSchema.validate({
        username: '111111111111111111111111111111111111111111111111111111111',
        password: 'correct',
        repeat_password: 'correct',
        email: 'valid@valid.com',
      });
      expect(error.message).toContain('username');
      expect(error.message).toContain('less than or equal to 30');
    });

    test('can validate password bad format', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: 1100,
        repeat_password: 1100,
        email: 'valid@valid.com',
      });
      expect(error.message).toBe('"password" must be a string');
    });

    test('can validate password - min length', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: '',
        repeat_password: '',
        email: 'valid@valid.com',
      });
      expect(error.message).toContain('password');
      expect(error.message).toContain('is not allowed to be empty');
    });

    test('can validate password - max length', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: '1111111111111111111111111111111111111',
        repeat_password: '1111111111111111111111111111111111111',
        email: 'valid@valid.com',
      });
      expect(error.message).toContain('password');
      expect(error.message).toContain('less than or equal to 30');
    });

    test('repeat password must exactly be password - pass', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: 'password should be same',
        repeat_password: 'password should be same',
        email: 'valid@valid.com',
      });
      expect(error).toBeFalsy();
    });

    test('repeat password must exactly be password', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: 'password should be same',
        repeat_password: 'not the same',
        email: 'valid@valid.com',
      });
      expect(error.message).toContain('"repeat_password" must be [ref:password]');
    });

    test('email must be in correct format - invalid domain', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: 'password should be same',
        repeat_password: 'password should be same',
        email: 'abc@invalid',
      });
      expect(error.message).toContain('email');
      expect(error.message).toContain('must be a valid email');
    });

    test('email must be in correct format - invalid identifier', () => {
      const { error } = signupSchema.validate({
        username: 'correct',
        password: 'password should be same',
        repeat_password: 'password should be same',
        email: '@invalid.com',
      });
      expect(error.message).toContain('email');
      expect(error.message).toContain('must be a valid email');
    });
  });
});
