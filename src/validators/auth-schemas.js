const Joi = require('@hapi/joi');

const signupSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
  password: Joi.string().pattern(/^[a-zA-Z0-9]{3,30}$/).required(),
  repeatPassword: Joi.ref('password'),
  email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'org'] } }),
});

module.exports = {
  signupSchema,
};
