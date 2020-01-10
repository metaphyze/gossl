# gossl
A simple proxy server that can easily provide HTTPS support through the Let's Encrypt certificate authority.  It can also serve static  content while proxying requests to other servers. 

### Example: Host static content over HTTPS
Here's how you could serve static content through HTTPS.  You might want to do this just to give your site visitors a warm fuzzy feeling from the little lock icon in the browser.  Sure, it's static content, but they don't know that.

    /home/ubuntu> sudo ./gossl -staticDir=/path/to/your/static/content/dir -domains=mydomain.com,www.mydomain.com
    
### Example: Run your primary server on a non-public port and proxy to it through gossl to provide HTTPS    
Of course, you'll first have to ensure that your domain name or names are actually pointed to your server through your DNS.  Also, it's important to not expose your primary server port(8080, in this example) publicly.

    /home/ubuntu> sudo ./gossl -simpleProxy=http://localhost:8080 -domains=mydomain.com,www.mydomain.com

This lets you write your server in whatever language you want, and lets gossl worry about the HTTPS.  This might be useful if it's difficult to set up HTTPS in your preferred development language or framework.

### Example: Proxy to multiple servers through a mapping and serve static content
First, you'll need to write a proxy configuration file in json.  Here's an example.

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

Now pass the configuration file to gossl.

    /home/ubuntu> ./gossl -proxyConfigFile=/path/to/proxy.config \
                  -staticDir=/path/to/your/static/content/dir \
                  -domains=mydomain.com,www.mydomain.com

## Installing gossl as a service on Linux (systemd) so that it starts on machine boot
You would most likely want to run gossl as a service.  gossl itself will provide you the instructions.

    /home/ubuntu> ./gossl -serviceInstallationInstructions
    
Which will print out this.

    Service installation instruction for Linux using systemd.
    First create a service file (myservice.service, for example) with the following format.
    The working directory doesn't really matter.
    The ExecStart command will have YOUR specific proxy setup.  This is JUST AN EXAMPLE.
    Also, don't include the "-------"s in your file.
    ------------------------------------------------------------------------------
    [Unit]
    Description=My Proxy Service
    After=network.target

    [Service]
    WorkingDirectory=/some/unimportant/directory

    ExecStart=/path/to/gossl -simpleProxy=http:localhost:8080 -domains=mydomain.com,www.mydomain.com
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    ------------------------------------------------------------------------------

    Next copy this service file to /etc/systemd/system, reload the daemon, start the service, and enable it (so that it runs on machine reboot):
    > sudo cp myservice.service /etc/systemd/system/
    > sudo systemctl daemon-reload
    > sudo systemctl start myservice.service
    > sudo systemctl enable myservice.service

    To stop the service:
    > sudo systemctl stop myservice.service

    To disable the service so that it doesn't start on system reboot:
    > sudo systemctl stop myservice.service
    > sudo systemctl disable myservice.service

    To re-enable the service:
    > sudo systemctl start myservice.service
    > sudo systemctl enable myservice.service

    If you update the service file, you'll to do this:
    > sudo systemctl stop myservice.service
    > sudo systemctl daemon-reload
    > sudo systemctl start myservice.service

    To debug problems with starting the service
    >sudo systemctl status myservice.service

    To see the service's current output (also useful for debugging)
    > sudo journalctl -u myservice.service -f

### Command line options.
Here's the complete list of command line options.  If you're serving static content, you should pay particular attention to the cacheControl options. Not that you do NOT have to use gossl to server HTTPS requests.  You can run it over regular your HTTP on any port you want.  You could even run it over HTTPS on a different port though you probably wouldn't want to do that. 

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
