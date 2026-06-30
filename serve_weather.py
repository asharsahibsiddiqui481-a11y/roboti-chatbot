import os, http.server, socketserver, functools

PORT = int(os.environ.get('PORT', 3001))
Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory='public')
Handler.log_message = lambda *a: None

with socketserver.TCPServer(('', PORT), Handler) as httpd:
    print(f'Weather app at http://localhost:{PORT}/weather.html')
    httpd.serve_forever()
