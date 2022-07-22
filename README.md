# yxorp-edon

A nodejs-based reverse-proxy, fulfilling the same basic function as NGINX, but with less features.

The reason for creating yxorp-edon is that NGINX does not support TLS renegotiation for requesting client certificates, and moreover the NGINX project refuses to consider adding this feature (WONTFIX).   This a feature I wanted to implement, because of my longstanding interest in client PKI certficates; I work for the US Department of Defense, where we have ~3M employees with PKI certs on smartcards.  

That said, the current status of TLS renegotiation is that it's basically unworkable.  I am using this code for my personal website, but there's little reason for anyone else to use this (if I weren't emotionally invested in this, I'd use NGINX) except as an example for how to use node-http2-proxy.

So... I created my own reverse-proxy service in nodejs, 'yxorp-edon' ('node-proxy' reversed, natch).  I  implemented reactive client certificates, such that certain URLs ('/pki/') would request client certificates and the yxorp-edon would generate a JSON Web Token and set it into a cookie. 

Later, when I implemented SPDY, I broke my prototype client certificate code.

In Spring 2019, I implemented HTTP/2, which broke things worse.  It is not possible at the present time to implement reactive client certificates over HTTP/2 for technical reasons that I discovered only after beating my head against the problem for a month.   

It is my current intent to downgrade the recommended implementation to HTTP/1.1 and TLS 1.2 and make the the certs work again. (2019-11-07)
