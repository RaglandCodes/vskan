const http = require('http');
const https = require('https');
const url = require('url');

// Configuration
const PORT = 8000;

// Create the proxy server
const server = http.createServer((clientReq, clientRes) => {
    const parsedUrl = url.parse(clientReq.url);

    // Log the request
    console.log(`[${new Date().toISOString()}] ${clientReq.method} ${clientReq.url}`);
    console.log('Headers:', JSON.stringify(clientReq.headers, null, 2));

    // Options for the proxied request
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.path,
        method: clientReq.method,
        headers: clientReq.headers
    };

    // Choose protocol based on the target URL
    const proxyProtocol = parsedUrl.protocol === 'https:' ? https : http;

    // Create the proxied request
    const proxyReq = proxyProtocol.request(options, (proxyRes) => {
        // Log the response
        console.log(`[${new Date().toISOString()}] Response Status: ${proxyRes.statusCode}`);
        console.log('Response Headers:', JSON.stringify(proxyRes.headers, null, 2));

        // Set the status code and headers from the proxied response
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);

        // Pipe the proxied response to the client response
        proxyRes.pipe(clientRes);
    });

    // Handle errors in the proxied request
    proxyReq.on('error', (err) => {
        console.error('Proxy Request Error:', err);
        clientRes.writeHead(500);
        clientRes.end('Proxy Error: ' + err.message);
    });

    // Pipe the client request to the proxied request
    clientReq.pipe(proxyReq);
});

// Handle server errors
server.on('error', (err) => {
    console.error('Server Error:', err);
});

// Start the server
server.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});