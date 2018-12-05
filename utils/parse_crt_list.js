"use strict";

var fs = require('fs');

var data = fs.readFileSync("DoD_CAs.pem");

var output = "";

//process.stdout.write(data);

var re = /(?:(subject=(?:[^\n]+))\n(issuer=(?:[^\n]+))\n(-----BEGIN CERTIFICATE-----(?:[^\-]+)-----END CERTIFICATE-----)\s*)/gm

/* 
res [0] = complete match
res [1] = subject line
res [2] = issuer line
res [3] = cert block
*/
//var res = pattern.exec(data);


var res;
while ((res = re.exec(data)) !== null) {
  if (res[1].match(/EMAIL|Root/)) {
//    console.log("subject ", res[1]);
//    console.log("issuer  ", res[2]);
    output += res[0];
  }
//  var msg = 'Found ' + res[3] + '. ';
//  var msg += 'Found ' + res[3] + '. ';
//  msg += 'Next match starts at ' + re.lastIndex;
//  console.log(msg);
}
//console.log(JSON.stringify(res, null," "));

fs.writeFile("../conf/email-only.pem", output, 'utf8', function(err) {
if (err) { console.log(err); } });
