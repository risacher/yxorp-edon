"use strict";

var fs = require('fs');

var data = fs.readFileSync("dod_ca.crt");

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
    console.log("subject ", res[1]);
    console.log("issuer  ", res[2]);
//  var msg = 'Found ' + res[3] + '. ';
//  var msg += 'Found ' + res[3] + '. ';
//  msg += 'Next match starts at ' + re.lastIndex;
//  console.log(msg);
}
//console.log(JSON.stringify(res, null," "));
