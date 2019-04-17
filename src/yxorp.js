"use strict";

process.title = "yxorp (nodejs)";

const fs = require('fs');
const http = require('http');
const https = require('https');
const util = require('util');
const constants = require('constants');
const httpProxy = require('http-proxy');
const proxyTable = require('./proxy-table.js');
const ocsp = require('ocsp');
const repl = require('repl');
const jwt = require('jsonwebtoken');
var tls = require('tls');
//tls.CLIENT_RENEG_LIMIT = 2; //default is 3, which should be okay
//tls.CLIENT_RENEG_WINDOW = 1 / 0;
var ocspCache = new ocsp.Cache();

var debug = {
  "proxy": true,
  "proxy-headers": false,
  "ocsp": false,
  "routing": true,
  "config": true,
  "reneg": true,
  'jwt': true,
  'tls': true,
  'modules': true,
  'error': true
};

const outHeadersKey = Object.getOwnPropertySymbols(new http.OutgoingMessage())
      .filter((e,i,a) => {return (e.toString() === "Symbol(outHeadersKey)"); })[0];

var table;

function log (category, args) {
  if (debug[category]) {
    console.log(Array.prototype.slice.call(arguments, 1));
  }
}

var config, config_file = "conf/proxyconf.json";
config_file = fs.readFileSync(config_file, "utf8");

try{ 
    config = JSON.parse(config_file);
} catch (err) {
  log('error', "error parsing config");
  log('error', "error was "+ err.message);
}

var jwtKey = fs.readFileSync(config.jwtKey, "utf8");

var read_routes = function(event, filename) {
    var routes_file = fs.readFileSync(config.routes);
    var routes_json;
    try {
	      routes_json = JSON.parse(routes_file);
    } catch (err) {
	      log('error', "error parsing json file");
	      log('error', "routes_file: ", routes_file);
	      log('error', "routes_json: ", routes_json);
	      log('error', "error was "+ err.message);
    }
    if (typeof(routes_json) == 'object') {
	      table = new proxyTable.ProxyTable({router: routes_json});
	      log('config', "routes: ", routes_json);
    } else {
	      log('error', "routes_json not an object: ", typeof(routes_json));
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

// I think the API changed and req and res will never be defined here
proxy.on('error', function(err, req, res) {
    log('error', "prox error: ", err, req, res);
    if (res.writeHead && res.end) {
        res.writeHead(502);
        res.end("502 Bad Gateway\n\n" + JSON.stringify(err, null, "  "));
    }
});

// If it ain't Baroque, don't fix it
proxy.on('proxyReq', function(proxyReq, req, res, options) {
  log ('proxy-headers', "proxyReq headers: ", proxyReq[outHeadersKey] );
//    proxyReq.setHeader('X-Forwarded-For', req.remoteAddr);
});

var optClientAuth = {
  requestCert: true,
  rejectUnauthorized: true
};

//
// proxyRes is fired when the response is received from the downstream (target) server
// Status code 496 is an unofficial code used by NGINX as "SSL Certificate Required"
proxy.on('proxyRes', function (proxyRes, req, res) {
  if (proxyRes.statusCode !== 200) {
    log('proxy', 'RAW Response from the target', JSON.stringify(proxyRes.statusCode, true, 2));
  }
  if (proxyRes.statusCode == 496) {
    proxyRes.statusCode = 302;
    var socket = req.connection;
    try {
      log('reneg', 'attempting renegotiation:');
      var result = socket.renegotiate(optClientAuth, function(err){
        log('reneg', "inside reneg callback");
        if (!err) {
          log('reneg', 'redirecting to ', proxyRes.headers.Location);
          res.setHeader('Location', proxyRes.headers.Location);   
          res.writeHead(302);
          res.end("302: Redirecting after TLS renegotiation");
          
        } else {
          log('error', "err from reneg: ", err.message);
        }
      });
    } catch (e) {
      log('error', "entering catch block");
      log('error', e);
      log('error', "leaving catch block");
    }
    log('reneg', 'attempted renegotiation');
  }
});

                                 

var https_options = {
  key: fs.readFileSync(config.serverKey, 'utf8'),
  cert: fs.readFileSync(config.serverCert, 'utf8'),
  ca: parseCertChain(fs.readFileSync(config.CACerts, 'utf8')),
  secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
  //secureOptions:require('constants').SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
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
                                  
function getClientCert(req, res, cb) {
  var socket = req.connection;
  var result = socket.renegotiate(optClientAuth, function(err){
    if (!err && req.connection.getPeerCertificate()) {
      // catch errors - getPeerCertificate() can be undef if user something goes wrong
      var token = jwt.sign({CN: req.connection.getPeerCertificate().subject.CN,
                            exp: Math.floor(new Date().getTime()/1000) + 7*24*60*60,
                            iat: Math.floor(Date.now() / 1000) - 30 },
                           jwtKey);
      log('jwt', 'jwt:', token);
      
      res.setHeader('Set-Cookie', ['jwt='+token+'; Path=/; Secure']);   
      cb(req, res);
      
    } else {
      log('error', err?err.message:"no cert");
    }
  });
}

var listener = function(req, res) {
  
  log('proxy',   req.method, req.headers.host, req.url, req.socket.localPort);
  //* do loadable module here */
  if (req.url == '/pki/') { 
    log('jwt', "PKI CODE ACTIVATED!");
    var socket = req.connection;
    var result = socket.renegotiate(optClientAuth, function(err){
      log('jwt', "inside hardcoded renegotiate callback");
      if (!err && req.connection.getPeerCertificate()) {
        // catch errors - getPeerCertificate() can be undef if something goes wrong
        var token = jwt.sign({CN: req.connection.getPeerCertificate().subject.CN,
                              exp: Math.floor(new Date().getTime()/1000) + 7*24*60*60,
                              iat: Math.floor(Date.now() / 1000) - 30 },
                             jwtKey);
        log('jwt', 'jwt:', token);
        
        res.setHeader('Set-Cookie', ['jwt='+token+'; Path=/; Secure']);   
        res.writeHead(200);
        res.end("<pre>"
                +JSON.stringify(req.connection.getCipher(),null, "  ")
                +"\n"
                +JSON.stringify(req.connection.getPeerCertificate(),null, "  ")
                +"</pre>"
                +"Authenticated Hello World\n");
        //        cb(req, res);
        
      } else {
        log('error', err?err.message:"no cert");
      }
    });
    return;
  }
  
  if (!req.headers.host && config.defaultTarget) {
    req.headers.host = config.defaultTarget;
  }
  
  var target = table.getProxyLocation(req);
  log('proxy',  'target: ', target );
  
  
  if (null == target) {
    log ('routing', "UNMATCHED request: ", req.url);
    res.writeHead(502);
    res.end("502 Bad Gateway\n\n" + "UNMATCHED request: "+ req.url);
  } else {
    proxy.web(req, res, { target: target });
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


//log('error', https_options);

var server = http.createServer(listener).listen(80);
var httpsServer = https.createServer(https_options, listener).listen(443);

// Simpleminded TLS session store
// This leaks memory I think, in that it never forgets old sessions
// 
var tlsSessionStore = {};
httpsServer.on('newSession', function(id, data, cb) {
    log('tls', "new tls session", id);
    tlsSessionStore[id] = data;
    cb();
});
httpsServer.on('resumeSession', function(id, cb) {
    log('tls', "resume tls session", id);
    cb(null, tlsSessionStore[id] || null);
});

httpsServer.on('tlsClientError', function(e, socket) {
    log('tls', "tlsClientError - ", e.message);
});

//log('error', httpsServer);

ocsp.getOCSPURI(https_options.cert, function(err, uri) { 
    if( err ) {
        log('ocsp', "No OCSP URI, disabling OCSP: ", err);
    } else {
        httpsServer.on('OCSPRequest', function(cert, issuer, cb) {
            log('ocsp', "OCSP request");
            ocsp.getOCSPURI(cert, function(err, uri) {
                log('ocsp', "OCSP cert", cert);
                log('ocsp', "OCSP issuer", issuer);
                
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
                        log('ocsp', "OCSP hit", req.id);                
                        return cb(null, res.response);
                    }
                    ocspCache.request(req.id, options, function(a,b) {
                        log('ocsp', "OCSP miss", req.id);
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
    log('proxy', "UPGRADE", req.url, socket.localPort);
    var target = table.getProxyLocation(req);
    if (null != target) {
	      proxy.ws(req, socket, head, {target: target});
    }
};

server.on('upgrade', upgrade);
httpsServer.on('upgrade', upgrade);



var mods = {};
var mod_names = [];
var modDir = "/modules/";
var lastErr; 

function loadMod(modName) {
    //     // What if the module was already loaded?  Reload it, I guess.
    unloadMod(modName);
    
    var path = process.cwd()+modDir+modName;
    try {
        log('modules', "begin loading "+modName);
        mods[modName] = require(path);
        mod_names.push(modName);
        if (typeof mods[modName]['load'] == 'function') {
            log('modules', "calling load "+modName);
            mods[modName]['load'](this);
        }
        log('modules', "done loading "+modName);
    } catch (e) {
        log('error', "error while loading module "+modName);
        log('error', e);
        lastErr = e;
        return e;
    }
    return;
}

function unloadMod(modName) {
    log('modules', "req unload '%s'",modName);
    if (mods[modName]) {
        if (typeof mods[modName]['unload'] == 'function') {
            log('modules', "calling unload "+modName);
            try {
                mods[modName]['unload'](this);
            } catch (e) {
                log('error', "error while loading module "+modName);
                log('error', e);
                lastErr = e;
                // don't return the error because we still should try to unload it.
                // return e;
            }
        }
        delete mods[modName];
        var index = mod_names.indexOf(modName);    
        if (index !== -1) {
            mod_names.splice(index, 1);
        }
    }
    var path = process.cwd()+modDir+modName;
    if (! /\.js$/.test(path)) { path += '.js'; };
    log('modules', "path to unload: ",path);
    path = require.resolve(path);
    log('modules', "resovled path to unload: ",path);

    if (require.cache[path]) {
        delete require.cache[path];
    };
}



function testResolve(path) {
    log('modules', require.resolve(path));
//    log('error', require);
}

// start REPL 

const r = repl.start('> ');
Object.defineProperty(r.context, 'loadMod', {
  configurable: false,
  enumerable: true,
  value: loadMod
});
Object.defineProperty(r.context, 'testResolve', {
  configurable: false,
  enumerable: true,
  value: testResolve
});
Object.defineProperty(r.context, 'unloadMod', {
  configurable: false,
  enumerable: true,
  value: unloadMod
});
Object.defineProperty(r.context, 'debug', {
  configurable: true,
  enumerable: true,
  value: debug
});
// end REPL
