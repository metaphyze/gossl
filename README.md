# gossl
A simple proxy server that can easily provide HTTPS support through Let's Encrypt certificate authority.  It can also serve static content while proxying requests to other servers. Here are the command line options.

    -cacheControlMaxAgeInSeconds int
        Only used when serving static files.
        For example, -cacheControlMaxAgeInSeconds=86400
        The maxium time in seconds that the response can be cached. (default 86400)
    -cacheControlPrivate
        Only used when serving static files.
        For example, -cacheControlPrivate
        It indicates that the response can be cached only by clients.  It cannot be used with -cacheControlPublic.
    -cacheControlPublic
        Only used when serving static files.
        For example, -cacheControlPublic
        It indicates that the response can be cached by clients and other proxies.  It cannot be used with -cacheControlPrivate.
    -certCacheDir string
        Directory where certificates are stored
        For example, -certCacheDir=/path/to/cert/dir
        If not specified, a directory will be created in /tmp.
        IMPORTANT NOTE: If you use a temp directory, it may be deleted on machine reboot.
        This could be important if your machine reboots frequently since Let's Encrypt is subject to rate limits.
        See:  https://letsencrypt.org/docs/rate-limits/
    -domains string
        Comma delineated list of domains for which HTTPS requests should be accepted
        For example, -domains=yourdomain.com,www.yourdomain.com
        Be sure your nameservers are pointing your domain(s) to this server's ip address.
    -dontGzipStaticResponse
        Only used when serving static files.
        For example, -dontGzipStaticResponse
        By default, responses served from the static content directory WILL be gzipped.  This option turns that OFF.
        You probably don't want this.
    -httpPort int
        Port on which to receive HTTP requests
        For example, -httpPort=8080 (default 80)
    -httpsPort int
        Port on which to receive HTTPS requests
        For example, -httpsPort=4443 (default 443)
    -idleTimeoutInMs int
        Socket idle timeout in milliseconds
        For example, -idleTimeoutInMs=5000 (default 120000)
    -proxyConfigFile string
        JSON file containing the proxy mappings
        For example, -proxyConfigFile=/path/to/proxy.config
        Examples files:
        Proxy requests inbound to /proxy/api to /api on a different server via https.
        -----------------------------------------------------------------------------
        {
          "Mappings" : [
              {
                "localPath": "/proxy/api",
                "remotePath": "/api",
                "host": "yourserver.com",
                "useHTTPS": true
              }
            ]
        }

        Proxy requests inbound to /api to /api on localhost via http.
        -------------------------------------------------------------
        {
          "Mappings" : [
              {
                "localPath": "/api",
                "remotePath": "/api",
                "host": "localhost",
                "useHTTPS": false,
                "port" : 8080
              }
            ]
        }

        Proxy requests inbound to / to / on localhost:8080 via http.  This is equivalent to -simpleProxy=http:localhost:8080.
        ---------------------------------------------------------------------------------------------------------------------
        {
          "Mappings" : [
              {
                "localPath": "/",
                "remotePath": "/",
                "host": "localhost",
                "useHTTPS": false,
                "port" : 8080
              }
            ]
        }

        Proxy requests inbound to /api1 to /api on yourdomain1.com via https, and proxy requests inbound to /api2 to /api on yourdomain2 via http
        -----------------------------------------------------------------------------------------------------------------------------------------
        {
          "Mappings" : [
              {
                "localPath": "/api1",
                "remotePath": "/api",
                "host": "yourdomain.com",
                "useHTTPS": true
              },
              {
                "localPath": "/api2",
                "remotePath": "/api",
                "host": "localhost",
                "useHTTPS": false
              }
            ]
        }

    -readTimeoutInMs int
        Socket read timeout in milliseconds
        For example, -readTimeoutInMs=5000 (default 10000)
    -serviceInstallationInstructions
        Display instructions on how to set gossl up as a service using systemd (Linux only instructions)
    -simpleProxy string
        [required HTTP/HTTPS]://[required HOSTNAME/IPADDRESS]:[optional port]
        For example, -simpleProxy=https://yourdomain.com or -simpleHost=http://localhost:8080
    -staticDir string
        Directory of static content to serve
        For example, -staticDir=/path/to/static/content/dir
        If -proxyConfigFile is specified, the request will first be checked against proxy mappings.
        If no proxy mapping is found, then we attempt to serve the request from this static content.
    -version
        Display version number, which by the way is 1.0
    -writeTimeoutInMs int
        Socket write timeout in milliseconds
        For example, -writeTimeoutInMs=5000 (default 10000)
