// Required libraries
const crypto = require('crypto-js');
const library = require('../library/library');
const _ = require('lodash');

exports.authenticate = (accessKey,secretKey,myMethod,host,myPath,region,myService)=>{

if(_.isEmpty(accessKey) || _.isEmpty(secretKey) || _.isEmpty(myMethod)|| _.isEmpty(host) || _.isEmpty(myPath) || _.isEmpty(region) ||_.isEmpty(myService))
  console.log('Cannot send empty values');
//amzDate
var amzDate = library.getAmzDate(new Date().toISOString());

//authDate
var authDate = amzDate.split("T")[0];

// payload
var payload = '';

// get the SHA256 hash value for our payload
var hashedPayload = crypto.SHA256(payload).toString();

//canonical request
var canonicalReq =  library.getCanonicalRequest(myMethod,myPath,host,hashedPayload,amzDate);

// hash the canonical request
var canonicalReqHash = crypto.SHA256(canonicalReq).toString();

// form our String-to-Sign
var stringToSign =  library.stringToSign(amzDate,authDate,region,myService,canonicalReqHash);
// signing key
var signingKey = library.getSignatureKey(crypto, secret_key, authDate, region, myService);

// final signature
var authKey = crypto.HmacSHA256(stringToSign, signingKey);

// final authorization header
var authString  = library.authString(access_key,authDate,region,myService,authKey);

// final header
console.log(headers = {
  'Authorization' : authString,
  'Host' : host,
  'x-amz-date' : amzDate,
  'x-amz-content-sha256' : hashedPayload,
  'X-Amz-Security-Token' : sessionToken
});
}