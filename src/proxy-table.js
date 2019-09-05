/*
  proxy-table.js: Lookup table for proxy targets in node.js

  Copyright (c) 2019 Dan Risacher
  Copyright (c) 2010 Charlie Robbins

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/* 2019: This code was borrowed from the old node-proxy a thousand
   years ago, which left much unused code .  Stripped out all unused
   code for yxorp */

var url = require('url');

//
// ### function ProxyTable (router)
// #### @router {Object} Object containing the host based routes
// Constructor function for the ProxyTable responsible for getting
// locations of proxy targets based on ServerRequest headers; specifically
// the HTTP host header.
//
var ProxyTable = exports.ProxyTable = function (options) {

  this.target       = options.target || {};

  if (typeof options.router === 'object') {
    //
    // If we are passed an object literal setup
    // the routes with RegExps from the router
    //
    this.setRoutes(options.router);
  }
  else {
    throw new Error('Cannot parse router with unknown type: ' + typeof router);
  }
};

//
// ### function setRoutes (router)
// #### @router {Object} Object containing the host based routes
// Sets the host-based routes to be used by this instance.
//
ProxyTable.prototype.setRoutes = function (router) {
    if (!router) {
	throw new Error('Cannot update ProxyTable routes without router.');
    }
    
    var self = this;
    this.router = router;
    
    this.routes = [];
    
    Object.keys(router).forEach(function (path) {
	let routeTarget, routeOptions;
	if (typeof(router[path]) === 'object') {
	    routeTarget = router[path].target;
	    routeOptions = Object.assign({}, router[path]);
	    delete routeOptions.target;
	} else if (typeof(router[path]) === 'string') {
	    routeTarget = router[path];
	    routeOptions = undefined;
	}
	
	if (!/http[s]?/.test(routeTarget)) {
	    routeTarget = (self.target.https ? 'https://' : 'http://')
		+ routeTarget;
	}
	    
	console.log('BOOP', path, routeTarget, routeOptions);
	var target = url.parse(routeTarget),
	    defaultPort = self.target.https ? 443 : 80;
	
	//
	// Setup a robust lookup table for the route:
	//
	//    {
	//      source: {
	//        regexp: /^foo.com/i,
	//        sref: 'foo.com',
	//        url: {
	//          protocol: 'http:',
	//          slashes: true,
	//          host: 'foo.com',
	//          hostname: 'foo.com',
	//          href: 'http://foo.com/',
	//          pathname: '/',
	//          path: '/'
	//        }
	//    },
	//    {
	//      target: {
	//        sref: '127.0.0.1:8000/',
	//        url: {
	//          protocol: 'http:',
	//          slashes: true,
	//          host: '127.0.0.1:8000',
	//          hostname: '127.0.0.1',
	//          href: 'http://127.0.0.1:8000/',
	//          pathname: '/',
	//          path: '/'
	//        }
	//    },
	//
	self.routes.push({
	    source: {
		regexp: new RegExp('^' + path, 'i'),
		sref: path,
		url: url.parse('http://' + path)
	    },
	    target: {
		sref: target.hostname + ':' + (target.port || defaultPort) + target.path,
		url: target,
		options: routeOptions
	    }
	});
    });
    console.log(self.routes);
};


//
// ### function getProxyLocation (req)
// #### @req {ServerRequest} The incoming server request to get proxy information about.
// Returns the proxy location based on the HTTP Headers in the  ServerRequest `req`
// available to this instance.
//
ProxyTable.prototype.getProxyLocation = function (req) {
    if (!req || !req.headers || !req.headers.host) {
	return null;
    }
    
    var targetHost = req.headers.host.split(':')[0];
    var target = targetHost + req.url;
    for (var i in this.routes) {
	var route = this.routes[i];
	if (target.match(route.source.regexp)) {
            //
            // Attempt to perform any path replacement for differences
            // between the source path and the target path. This replaces the
            // path's part of the URL to the target's part of the URL.
            //
            // 1. Parse the request URL
            // 2. Replace any portions of the source path with the target path
            // 3. Set the request URL to the formatted URL with replacements.
            //
            var parsed = url.parse(req.url);
	    
            parsed.path = parsed.path.replace(
		route.source.url.pathname,
		route.target.url.pathname
            );
	    
            req.url = url.format(parsed);
            return {
		protocol: route.target.url.protocol.replace(':', ''),
		hostname: route.target.url.hostname, //added for compat w/ http2-proxy
		host: route.target.url.hostname,
		path: parsed.path,
		port: route.target.url.port
		    || (this.target.https ? 443 : 80),
		options: route.target.options
            };
	}
    }
    return null;
};

