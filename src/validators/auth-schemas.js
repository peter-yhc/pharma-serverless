const Joi = require('@hapi/joi');

const signupSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
  password: Joi.string().max(30).required(),
  repeatPassword: Joi.ref('password'),
  email: Joi.string().email({ minDomainSegments: 2 }),
});

module.exports = {
  signupSchema,
};
