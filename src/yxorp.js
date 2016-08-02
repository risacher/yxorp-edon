"use strict";


var fs = require('fs');
var http = require('http');
var https = require('https');
var util = require('util');
var constants = require('constants');
var httpProxy = require('http-proxy');
var proxyTable = require('./proxy-table.js');
var ocsp = require('ocsp');

var ocspCache = new ocsp.Cache();

var table;

var config, config_file = "conf/proxyconf.json";
config_file = fs.readFileSync(config_file, "utf8");

try{ 
    config = JSON.parse(config_file);
} catch (err) {
	  console.log("error parsing config");
	  console.log("error was "+ err.message);
}

var read_routes = function(event, filename) {
    var routes_file = fs.readFileSync(config.routes);
    var routes_json;
    try {
	      routes_json = JSON.parse(routes_file);
    } catch (err) {
	      console.log("error parsing json file");
	      console.log("routes_file: ", routes_file);
	      console.log("routes_json: ", routes_json);
	      console.log("error was "+ err.message);
    }
    if (typeof(routes_json) == 'object') {
	      table = new proxyTable.ProxyTable({router: routes_json});
	      console.log("routes: ", routes_json);
    } else {
	      console.log("routes_json not an object: ", typeof(routes_json));
    }
};

read_routes();
fs.watch(config.routes, {persistent: false}, read_routes);

//
// Create a proxy server with custom application logic
//
var proxy = httpProxy.createProxyServer({
    xfwd : true
});

proxy.on('error', function(err, req, res) {
    console.log("prox error: ", err);
    res.writeHead(502);
    res.end("502 Bad Gateway\n\n" + JSON.stringify(err, null, "  "));
});

// If it ain't Baroque, don't fix it
//proxy.on('proxyReq', function(proxyReq, req, res, options) {
//    console.log ("req", req);
//    proxyReq.setHeader('X-Forwarded-For', req.remoteAddr);
//});


var optClientAuth = {
    requestCert: true,
    rejectUnauthorized: true
};

var listener = function(req, res) {
    
    console.log(  req.method, req.headers.host, req.url, req.socket.localPort);
    //* do loadable module here */
    if (req.url == '/pki/') { 
        console.log("PKI CODE ACTIVATED!");
        var socket = req.connection;
        var result = socket.renegotiate(optClientAuth, function(err){
            if (!err) {
                console.log(req.connection.getPeerCertificate());
                
                res.writeHead(200);
                
                res.end("<pre>"
                        +JSON.stringify(req.connection.getCipher(),null, "  ")
                        +"\n"
                        +JSON.stringify(req.connection.getPeerCertificate(),null, "  ")
                        +"</pre>"
                        +"Authenticated Hello World\n");
                
            } else {
                console.log(err.message);
            }
        });
        return;
    }


    var target = table.getProxyLocation(req);
    console.log( 'target: ', target );


    if (null != target) {
	      proxy.web(req, res, { target: target });
    } else {
        console.log ("UNMATCHED request: ", req.url);
        res.writeHead(502);
        res.end("502 Bad Gateway\n\n" + "UNMATCHED request: "+ req.url);
    }
};

//
// Create your custom server and just call `proxy.web()` to proxy 
// a web request to the target passed in the options
// also you can use `proxy.ws()` to proxy a websockets request
//

function parseCertChain(chain) {
    chain = chain.split('\n');
    var ca = [];
    var cert = [];
    var line;
    while (chain.length > 0) {
        line = chain.shift();
        cert.push(line); 
        if (line.match(/-END CERTIFICATE-/)) {
            ca.push(cert.join('\n'));
            cert = [];
        }
    }
    return ca;
}

var https_options = {
    key: fs.readFileSync(config.serverKey, 'utf8'),
    cert: fs.readFileSync(config.serverCert, 'utf8'),
    ca: parseCertChain(fs.readFileSync(config.CACerts, 'utf8')),

    // https://certsimple.com/blog/a-plus-node-js-ssl
    ciphers: [
            "ECDHE-RSA-AES256-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "DHE-RSA-AES256-SHA384",
            "DHE-RSA-AES256-SHA256",
            "ECDHE-RSA-AES128-SHA256",
            "DHE-RSA-AES128-SHA256",
            "HIGH",
            "!aNULL",
            "!eNULL",
            "!EXPORT",
            "!DES",
            "!RC4",
            "!MD5",
            "!PSK",
            "!SRP",
            "!CAMELLIA"
        ].join(':')
};

//console.log(https_options);

var server = http.createServer(listener).listen(80);
var httpsServer = https.createServer(https_options, listener).listen(443);

// Simpleminded TLS session store
// This leaks memory I think, in that it never forgets old sessions
// 
var tlsSessionStore = {};
httpsServer.on('newSession', function(id, data, cb) {
    console.log("new tls session", id);
    tlsSessionStore[id] = data;
    cb();
});
httpsServer.on('resumeSession', function(id, cb) {
    console.log("resume tls session", id);
    cb(null, tlsSessionStore[id] || null);
});

httpsServer.on('tlsClientError', function(e, socket) {
    console.log('tlsClientError - ', e.message);
});

//console.log(httpsServer);

ocsp.getOCSPURI(https_options.cert, function(err, uri) { 
    if( err ) {
        console.log("No OCSP URI, disabling OCSP: ", err);
    } else {
        httpsServer.on('OCSPRequest', function(cert, issuer, cb) {
            console.log("OCSP request");
            ocsp.getOCSPURI(cert, function(err, uri) {
                console.log("OCSP cert", cert);
                
                if (err) {
                    return cb(err);
                }        
                
                var req = ocsp.request.generate(cert, issuer);
                var options = {
                    url: uri,
                    ocsp: req.data
                };
                
                ocspCache.probe(req.id, function(e, res) {
                    if (res) {
                        console.log('OCSP hit', req.id);                
                        return cb(null, res.response);
                    }
                    ocspCache.request(req.id, options, function(a,b) {
                        console.log('OCSP miss', req.id);
                        cb(a,b);
                    });
                });
                
            });
        });
    }
});


//
// Listen to the `upgrade` event and proxy the 
// WebSocket requests as well.
//

var upgrade = function (req, socket, head) {
    console.log("UPGRADE", req.url, socket.localPort);
    var target = table.getProxyLocation(req);
    if (null != target) {
	      proxy.ws(req, socket, head, {target: target});
    }
};

server.on('upgrade', upgrade);
httpsServer.on('upgrade', upgrade);

