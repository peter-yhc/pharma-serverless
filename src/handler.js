const AWS = require('aws-sdk');

const documentClient = new AWS.DynamoDB.DocumentClient({
  region: 'ap-southeast-2',
});

const getPatients = async () => {
  const patients = await documentClient
    .scan({
      TableName: 'PatientTable',
    })
    .promise();

  return {
    statusCode: 200,
    body: JSON.stringify({
      patients: patients.Items,
    }),
  };
};

const savePatient = async (patient) => {
  await documentClient
    .put({
      TableName: 'PatientTable',
      Item: patient,
    })
    .promise();

  return {
    statusCode: 201,
  };
}

// Use this code if you don't use the http event with the LAMBDA-PROXY integration
// return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
;

module.exports = {
  getPatients,
  savePatient,
};
