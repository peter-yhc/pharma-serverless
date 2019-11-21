/**
* References:
* https://yos.io/2017/09/03/serverless-authentication-with-jwt/
* https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html
* */
const JWT = require('jsonwebtoken');
const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');
const { signupSchema } = require('./validators/auth-schemas');

const JWT_SECRET = '1aa4ed62-4f84-4afd-9e15-9ffa8c1c3ab9';

const documentClient = new AWS.DynamoDB.DocumentClient({
  region: 'ap-southeast-2',
});

// Help function to generate an IAM policy
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
};

const signup = async (request) => {
  const formData = JSON.parse(request.body);
  const { error } = signupSchema.validate(formData);
  if (error) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({
        message: 'Bad data format',
      }),
    };
  }
  const salt = bcrypt.genSaltSync(5);
  const hash = bcrypt.hashSync(formData.password, salt);

  await documentClient
    .put({
      TableName: 'AdminUserTable',
      Item: {
        username: formData.username,
        email: formData.email,
        password: hash,
      },
    })
    .promise();

  return {
    statusCode: 201,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
  };
};

const login = async (request) => {
  const { username, password } = JSON.parse(request.body);

  const scanResult = await documentClient
    .get({
      TableName: 'AdminUserTable',
      Key: {
        username,
      },
    })
    .promise();

  const userEntry = scanResult.Item;
  const result = bcrypt.compareSync(password, userEntry.password);
  if (result) {
    const token = JWT.sign({ username: userEntry.username }, JWT_SECRET, { expiresIn: '1h' });
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
        'Access-Control-Expose-Headers': '*',
        Authorization: token,
      },
    };
  }
  return {
    statusCode: 401,
  };
};

const authorize = async (request, context, callback) => {
  try {
    const token = request.authorizationToken;
    await JWT.verify(token, JWT_SECRET);
    const prefix = request.methodArn.split('/');
    callback(null, generatePolicy('user', 'Allow', `${prefix[0]}/*/patients`));
  } catch (err) {
    console.log('Error authorizing request', err, request);
    callback('Unauthorized');
  }
};

module.exports = {
  signup,
  login,
  authorize,
};
