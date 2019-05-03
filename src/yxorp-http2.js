"use strict";

const fs = require('fs');
//const http = require('follow-redirects').http;
const http = require('http');
const https = require('https');
const http2 = require('http2');
const proxy = require('http2-proxy');
const repl = require('repl');
const util = require('util');
const constants = require('constants');
//const httpProxy = require('http-proxy');
const proxyTable = require('./proxy-table.js');
const ocsp = require('ocsp');
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

/* as ugly a hack as ever I saw.  Fortunately, not needed */
const outHeadersKey = Object.getOwnPropertySymbols(new http.OutgoingMessage())
      .filter((e,i,a) => {return (e.toString() === "Symbol(outHeadersKey)"); })[0];

var table;

function log (category, args) {
  if (debug[category]) {
    console.log.apply(null, [category, ...Array.prototype.slice.call(arguments, 1)]);
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

const finalhandler = require('finalhandler');

const defaultWebHandler = (err, req, res) => {
  if (err) {
    console.error('proxy error', err)
    finalhandler(req, res)(err)
  }
}

const defaultWSHandler = (err, req, socket, head) => {
  if (err) {
    console.error('proxy error', err)
    socket.destroy()
  }
}

const route = function (req) {
  log('proxy',  'Incoming REQ:', req.method, req.url, req.socket.localAddress, req.socket.localPort);
  log('proxy-headers', 'Incoming REQ Headers', JSON.stringify(req.headers));
  if (req.headers[':authority']) { req.headers.host = req.headers[':authority'];}
  
  var target = table.getProxyLocation(req);
  if (target) { log('routing',  'target: ', JSON.stringify(target) ); }
    
  if (null == target) {
    log ('routing', "UNMATCHED request, attempt default target: ", req.url);
    req.headers.host = config.defaultTarget;
    target = table.getProxyLocation(req);
    if (target) { log('routing',  'target: ', JSON.stringify(target) ); }
    else { log('routing',  'UNMATCHED request with default target: ', JSON.stringify(target) ); }
  }
  return target;
}

const listener = function (req, res) {
  
  var target = route(req);
  
  if (null == target) {
    res.writeHead(502);
    res.end("502 Bad Gateway\n\n" + "MATCHLESS request: "+ req.headers.host+req.url);
  } else {
    proxy.web(req, res,
              { //hostname: target.host,
                //port: target.port,
                //protocol: target.protocol,
                onReq: (req, options) => {
                  
                  options.headers['x-forwarded-for'] = req.socket.remoteAddress;
                  options.headers['x-forwarded-port'] = req.socket.localPort;
                  options.headers['x-forwarded-proto'] = req.socket.encrypted ? 'https' : 'http';
                  options.headers['x-forwarded-host'] = req.headers['host'];
                  options.headers['host'] = req.headers['host'];
                  options.rejectUnauthorized = false;
                  options.trackRedirects = true;
                  options.host = target.host;                  
                  options.hostname = target.hostname;
                  options.port = target.port;
                  options.path = target.path;
                  options.protocol = target.protocol+':';
                  //                  log('proxy', "OPTIONS", options);
                  
                  var r = (target.protocol === 'http')?
                      http.request(options)
                      : https.request(options);
                  // this is evil black magic, but works for node's http clientRequest
                  //r[outHeadersKey].host = ['host', req.headers.host] ;
                  log('proxy-headers', 'proxyReq', r[outHeadersKey]);
                  return r;
                },
                // This breaks everything, for no obvious reason.
                // I don't know how to use onRes, which is poorly documented.
//                onRes: (req, resOrSocket, proxyRes, callback) => {
//                 log('proxy', 'REDIRECTS:', JSON.stringify(proxyRes.redirects));
//                return false;
//                }
              }, defaultWebHandler );
  }
};

const upgrade = function (req, socket, head) {
  
  log('proxy', "UPGRADE", req.url, socket.localPort);
  var target = route(req);
  if (null != target) {
    proxy.ws(req, socket, head, target, defaultWSHandler);
  } else {
    socket.close()
  }
};


var https_options;
var https_server;

function init_https() {
  https_options = {
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
    ].join(':'),
    allowHTTP1: true
  };
  if (https_server) { https_server.close(); }
  log('tls', "*** reloading https_server ***") ;
  https_server = http2.createSecureServer(https_options).listen({port:443});
  https_server.on('request', listener);
  https_server.on('upgrade', upgrade);
  ocsp.getOCSPURI(https_options.cert, function(err, uri) { 
    if( err ) {
      log('ocsp', "No OCSP URI, disabling OCSP: ", err);
    } else {
      https_server.on('OCSPRequest', function(cert, issuer, cb) {
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
}

var server = http.createServer({ allowHTTP1: true }).listen(80);
server.on('request', listener);
server.on('upgrade', upgrade);

init_https();
fs.watch(config.serverCert, {persistent: false}, init_https);

// start REPL 

const r = repl.start('> ');
Object.defineProperty(r.context, 'debug', {
  configurable: true,
  enumerable: true,
  value: debug
});
Object.defineProperty(r.context, 'table', {
  configurable: true,
  enumerable: true,
  value: table
});
// end REPL
