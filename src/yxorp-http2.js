"use strict";

const fs = require('fs');
//const http = require('follow-redirects').http;
const http = require('http');
const net = require('net');
const tls = require('tls');
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
//var tls = require('tls');
//tls.CLIENT_RENEG_LIMIT = 2; //default is 3, which should be okay
//tls.CLIENT_RENEG_WINDOW = 1 / 0;
var ocspCache = new ocsp.Cache();

//copied from http2-proxy
const CONNECTION = 'connection'
const HOST = 'host'
const KEEP_ALIVE = 'keep-alive'
const PROXY_AUTHORIZATION = 'proxy-authorization'
const PROXY_CONNECTION = 'proxy-connection'
const TE = 'te'
const FORWARDED = 'forwarded'
const TRAILER = 'trailer'
const TRANSFER_ENCODING = 'transfer-encoding'
const UPGRADE = 'upgrade'
const VIA = 'via'
const AUTHORITY = ':authority'
const HTTP2_SETTINGS = 'http2-settings'

var debug = {
    "proxy": false,
    "upgrade": true,
    "onRes": false,
    "proxy-headers": false,
    "ocsp": false,
    "routing": false,
    "config": true,
    "reneg": true,
    'jwt': true,
    'tls': true,
    'modules': true,
    'error': true
};


/* In node's http, a bunch of Symbols() are used as keys, but since
 * they are not exported from the module, there is no clean way to use
 * them outsode the module.  This is intentional, but for I wanted to
 * access those anyway.  So I found this evil hack to find a reference
 * to the opaque keys. */

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

//var jwtKey = fs.readFileSync(config.jwtKey, "utf8");

                                  
function getClientCert(req, res, cb) {
  var socket = req.connection;
  var result = socket.renegotiate(optClientAuth, function(err){
    if (!err) {
      // catch errors - getPeerCertificate() can be undef if user something goes wrong
      var token = jwt.sign({CN: req.connection.getPeerCertificate().subject.CN,
                            exp: Math.floor(new Date().getTime()/1000) + 7*24*60*60,
                            iat: Math.floor(Date.now() / 1000) - 30 },
                           jwtKey);
      log('jwt', token);
      
      res.setHeader('Set-Cookie', ['jwt='+token+'; Path=/; Secure']);   
      cb(req, res);
      
    } else {
      console.log(err.message);
    }
  });
}



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
fs.realpath(config.routes, (err, resolvedPath) => fs.watch(resolvedPath, {persistent: false}, read_routes));

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
    console.error('web proxy error', err)
    finalhandler(req, res)(err)
  }
}

const defaultWSHandler = (err, req, socket, head) => {
  if (err) {
    console.error('ws proxy error', err)
    socket.destroy()
  }
}

const route = function (req) {
    if (req.headers[':authority']) { req.headers.host = req.headers[':authority'];}
    log('proxy',  'Incoming REQ:', req.method, req.headers.host, req.url, req.socket.remoteAddress, req.socket.localPort);
    log('proxy-headers', 'Incoming REQ Headers', JSON.stringify(req.headers));
    
    var target = table.getProxyLocation(req);
    if (target) {
	target.method = req.method;
	log('routing',  'target: ', JSON.stringify(target) );
    }
    
    if (null == target) {
	log ('routing', "UNMATCHED request, attempt default target: ", req.url);
	req.headers.host = config.defaultTarget;
	target = table.getProxyLocation(req);
	if (target) { log('routing',  'target: ', JSON.stringify(target) ); }
	else { log('routing',  'UNMATCHED request with default target: ', JSON.stringify(target) ); }
    }
    if (target) { target.method = req.method; }
    return target;
}

var optClientAuth = {
  requestCert: true,
  rejectUnauthorized: true
};

const listener = function (req, res) {
  
    var target = route(req);
    if (null == target) {
	res.writeHead(502);
	res.end("502 Bad Gateway\n\n" + "MATCHLESS request: "+ req.headers.host+req.url);
	return;
    }

/* commented out because http2 cant do reactive client certs as of 2019-09-05    
    if (target.options && target.options.requestCert
	&& (req.connection.socket instanceof http2.Http2Stream)) {
	var socket = req.connection;
	console.log('socet', socket);
	var result = socket.renegotiate(optClientAuth, function(err){
	    if (!err) {
		console.log("inside hardcoded renegotiate callback");
		// catch errors - getPeerCertificate() can be undef if something goes wrong
//		var token = jwt.sign({CN: req.connection.getPeerCertificate().subject.CN,
//				      exp: Math.floor(new Date().getTime()/1000) + 7*24*60*60,
//				      iat: Math.floor(Date.now() / 1000) - 30 },
//				     jwtKey);
//		console.log('jwt:', token);
		
//		res.setHeader('Set-Cookie', ['jwt='+token+'; Path=/; Secure']);   
//		res.writeHead(200);
//		res.end("<pre>"
//			+JSON.stringify(req.connection.getCipher(),null, "  ")
		// 	+"\n"
		// 	+JSON.stringify(req.connection.getPeerCertificate(),null, "  ")
		// 	+"</pre>"
		// 	+"Authenticated Hello World\n");
		// //        cb(req, res);
		
	    } else {
		console.log(err.message);
	    }
	});
    }
*/	
  proxy.web(req, res, {
    onReq: (req, options) => {
      if (! options.headers) { options.headers={}; }
      //log('proxy-headers', 'arguments', options);
      if (req.socket) {
        req.socket.remoteAddress ? (options.headers['x-forwarded-for'] = req.socket.remoteAddress) : null;
        req.socket.localPort ? (options.headers['x-forwarded-port'] = req.socket.localPort) : null;
        options.headers['x-forwarded-proto'] = req.socket.encrypted ? 'https' : 'http';
      }
      if ( req.headers['host'] ) {
        options.headers['x-forwarded-host'] = req.headers['host'];
        options.headers['host'] = req.headers['host'];
      }
      options.rejectUnauthorized = false;
      options.trackRedirects = true;
      options.host = target.host;
      options.hostname = target.hostname;
      options.port = target.port;
      options.path = target.path;
      options.protocol = target.protocol+':';
      var r = (target.protocol === 'http')?
          http.request(options)
          : https.request(options);
      // this is evil black magic, but works for node's http clientRequest
      //r[outHeadersKey].host = ['host', req.headers.host] ;
      log('proxy-headers', 'proxyReq', r[outHeadersKey]);
      return r;
    },
    //		  onRes: onResHandler
  }, defaultWebHandler );
};

// basically lifted from http2-proxy/index.js, but copied here so I
// can add a log statement or otherwise mod it.
function onResHandler (req, res, proxyRes) {
  log('onRes', proxyRes.url, proxyRes.statusCode);
  const headers = setupHeaders(proxyRes.headers);
  res.statusCode = proxyRes.statusCode
  for (const [ key, value ] of Object.entries(headers)) {
    res.setHeader(key, value)
  }
  proxyRes.pipe(res)
}

// direct from http2-proxy/index.js
function sanitize (name) {
  return name ? name.trim().toLowerCase() : ''
}

function setupHeaders (headers) {
  const connection = sanitize(headers[CONNECTION])

  if (connection && connection !== CONNECTION && connection !== KEEP_ALIVE) {
    for (const name of connection.split(',')) {
      delete headers[name.trim()]
    }
  }

  // Remove hop by hop headers
  delete headers[CONNECTION]
  delete headers[KEEP_ALIVE]
  delete headers[TRANSFER_ENCODING]
  delete headers[TE]
  delete headers[UPGRADE]
  delete headers[PROXY_AUTHORIZATION]
  delete headers[PROXY_CONNECTION]
  delete headers[TRAILER]
  delete headers[HTTP2_SETTINGS]

  return headers
}

const upgrade = function (req, socket, head) {
    req.which = 'inbound';
    log('upgrade', "REQ HEADERS", req.headers, req.url);
    var target = route(req);
    if (null != target) {
	target.protocol = target.protocol.replace(/http$/, 'http:');
	log('upgrade', "TARGET OPTIONS", target);
	proxy.ws(req, socket, head, {
	    onReq: (req, options) => {
                options.host = target.host;                  
                options.hostname = target.hostname;
                options.port = target.port;
                options.path = target.path;
                var r = (target.protocol.match(/^(http|ws):?$/))?
		    http.request(options)
		    : https.request(options);
                return r;
	    }
	}, defaultWSHandler);
    } else {
	socket.close()
    }
};


var https_options;
var https_server;
var certwatcher;

function init_http2(port) {
  https_options = {
    allowHTTP1: true,
    key: fs.readFileSync(config.serverKey, 'utf8'),
    cert: fs.readFileSync(config.serverCert, 'utf8'),
      secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
//      requestCert: true,
//      rejectUnauthorized: false, 
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
//  if (config.CACerts) {
//    https_options['ca'] = parseCertChain(fs.readFileSync(config.CACerts, 'utf8'))
//  }

  if (https_server) { https_server.close(); }
  log('tls', "*** reloading https_server ***") ;
  https_server = http2.createSecureServer(https_options).listen({'port': port});
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

  if (0) {
    // this is just a hack to get the parsed certificate object from the tls context
    // specifically so to get the valid dates.  //NOT WORKING 2021-05-12
    let secureContext = tls.createSecureContext({
      cert: https_options.cert
    });
    let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
    https_server.cert = secureSocket.getCertificate();  // THIS DOES NOT WORK AND CRASHES
    log('tls', `cert valid from ${https_server.cert.valid_from}`);
    log('tls', `cert valid to ${https_server.cert.valid_to}`);
    secureSocket.destroy();
    // 
  }
  if (0) {  //this looks promising, but I think it needs a newer version of Node than I'm using

    const { X509Certificate } = require('crypto');
    const x509 = new X509Certificate(https_options.cert);
    log('tls', `cert.subject ${x509.subject}`);
  }

  
  if (certwatcher) { certwatcher.close(); } 
  fs.realpath(config.serverCert,
              (err, resolvedPath) => {
                log('tls', `watching for changes on ${resolvedPath}`);
                certwatcher = fs.watch(resolvedPath, {persistent: false}, init_http2);
              } );
}

function start_services() {
    for (const [port, service] of Object.entries(config.ports)) {
	if (service == 'http') {
	    console.log(`starting http server on ${port}`);
	    let server = http.createServer({ }).listen(parseInt(port,10));
	    server.on('request', listener);
	    server.on('upgrade', upgrade);
	}
	if (service == 'http2') {
	    console.log(`starting http2 server on ${port}`);
	    init_http2(parseInt(port,10));
	}
    }
}

start_services();
//init_https();

// start REPL 

var help = `REPL processes javascript, but the only two objects are debug and table
(and help)

you can say something like:
   debug.tls = false;
`;

const r = repl.start('> ');
Object.defineProperty(r.context, 'debug', {
  configurable: true,
  enumerable: true,
  value: debug
});
Object.defineProperty(r.context, 'help', {
  configurable: true,
  enumerable: true,
  value: help
});
Object.defineProperty(r.context, 'table', {
  configurable: true,
  enumerable: true,
  value: table
});
// end REPL
