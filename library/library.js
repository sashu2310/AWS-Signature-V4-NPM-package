const AWS = require('aws-sdk');

exports.getSignatureKey = function (Crypto, key, dateStamp, regionName, serviceName) {
    let kDate = Crypto.HmacSHA256(dateStamp, "AWS4" + key);
    let kRegion = Crypto.HmacSHA256(regionName, kDate);
    let kService = Crypto.HmacSHA256(serviceName, kRegion);
    let kSigning = Crypto.HmacSHA256("aws4_request", kService);
    return kSigning;
};
exports.getAmzDate = function (dateStr) {
    let chars = [":","-"];
    for (let i=0;i<chars.length;i++) {
      while (dateStr.indexOf(chars[i]) != -1) {
        dateStr = dateStr.replace(chars[i],"");
      }
    }
    dateStr = dateStr.split(".")[0] + "Z";
    return dateStr;
  };

exports.getCanonicalRequest = function(myMethod,myPath,host,hashedPayload,amzDate) {
                     return myMethod + '\n' +
                            myPath + '\n' +
                            '\n' +
                            'host:' + host + '\n' +
                            'x-amz-content-sha256:' + hashedPayload + '\n' +
                            'x-amz-date:' + amzDate + '\n' +
                            '\n' +
                            'host;x-amz-content-sha256;x-amz-date' + '\n' +
                            hashedPayload;
  return canonicalRequest;
}

exports.stringToSign = function(amzDate,authDate,region,myService,canonicalReqHash) {
                    return 'AWS4-HMAC-SHA256\n' +
                            amzDate + '\n' +
                            authDate+'/'+region+'/'+myService+'/aws4_request\n'+
                            canonicalReqHash;
}

exports.authString = function(access_key,authDate,region,myService,authKey) {
                  return  'AWS4-HMAC-SHA256 ' +
                          'Credential='+
                          access_key+'/'+
                          authDate+'/'+
                          region+'/'+
                          myService+'/aws4_request,'+
                          'SignedHeaders=host;x-amz-content-sha256;x-amz-date,'+
                          'Signature='+authKey;
}

exports.accessToken = async function() {
  let accessObject = new Object();
  let sts = new AWS.STS();
  let role = 'arn:aws:iam::620169180577:role/Cognito_HomexCloudDevAuth_Role'
   return new Promise(function(resolve,reject){
       let params = {
        DurationSeconds: 3600, 
        RoleArn: role, 
        RoleSessionName: "HomexRole"
       };
       sts.assumeRole(params, function(err, data) {
         if (err) return reject(err) // an error occurred
         else     
         {
          accessObject.accessKey = data.Credentials.AccessKeyId;
          accessObject.secretKey = data.Credentials.SecretAccessKey;
          accessObject.sessionToken = data.Credentials.SessionToken;
          return resolve(accessObject);
         }      
       });
      });
}

exports.replaceWithUnderScore= (thingname)=>{
  let thingName="";
  for(let i=0;i<thingname.length;i++)
  {
    if(thingname[i] == " ")
      thingName+= "";
    else
      thingName+= thingname[i];

  }
  return thingName;
}