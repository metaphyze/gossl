package main

import (
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/metaphyze/gossl/proxyconfig"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	url2 "net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const VERSION = "1.0"

const DEFAULT_READ_TIMEOUT_MS = 10000     // 10 seconds
const MIN_READ_TIMEOUT_MS = 1000          // 1 second
const MAX_READ_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

const DEFAULT_WRITE_TIMEOUT_MS = 10000     // 10 seconds
const MIN_WRITE_TIMEOUT_MS = 1000          // 1 second
const MAX_WRITE_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

const DEFAULT_IDLE_TIMEOUT_MS = 120 * 1000 // 2 minutes
const MIN_IDLE_TIMEOUT_MS = 5 * 1000       //  5 seconds
const MAX_IDLE_TIMEOUT_MS = 5 * 60 * 1000  // 5 minutes

var STATIC_CONTENT_DIR string
var CACHE_CONTROL_PRIVATE bool
var CACHE_CONTROL_MAX_AGE_IN_SECONDS int
var DONT_GZIP_STATIC_CONTENT_RESPONSES bool
var PROXY_CONFIG *proxyconfig.ProxyConfig

var reverseProxyMap map[string]*httputil.ReverseProxy
var proxyUrlMap map[string]*url2.URL
var simpleReverseProxy *httputil.ReverseProxy
var simpleProxyURL *url2.URL

type handler struct {
	protocol string
	port     int
}

func (theHandler *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	processRequest(theHandler, writer, request)
}

func processRequest(theHandler *handler, writer http.ResponseWriter, request *http.Request) {

	if simpleReverseProxy != nil {
		request.URL.Scheme = simpleProxyURL.Scheme

		if strings.EqualFold(simpleProxyURL.Scheme, "https") {
			request.Header.Set("X-Forwarded-Host", request.Host)
			request.Header.Set("X-Forwarded-Port", fmt.Sprintf("%v", theHandler.port))
			request.Header.Set("X-Forwarded-Proto", theHandler.protocol)

		}

		request.Host = simpleProxyURL.Host

		simpleReverseProxy.ServeHTTP(writer, request)
	} else {
		if PROXY_CONFIG != nil {
			lowercasePath := strings.ToLower(request.URL.Path)
			for _, proxyConfig := range PROXY_CONFIG.Mappings {
				localPath := proxyConfig.LocalPath
				if localPath == "/" || strings.EqualFold(lowercasePath, localPath) || strings.HasPrefix(lowercasePath, localPath+"/") {
					processProxyRequest(theHandler, proxyConfig, writer, request)
					return
				}
			}
		}

		if STATIC_CONTENT_DIR != "" {
			var sb strings.Builder
			if CACHE_CONTROL_PRIVATE {
				sb.WriteString("private, ")
			} else {
				sb.WriteString("public, ")
			}

			sb.WriteString(fmt.Sprintf("max-age=%v", CACHE_CONTROL_MAX_AGE_IN_SECONDS))
			writer.Header().Set("Cache-Control", sb.String())

			if DONT_GZIP_STATIC_CONTENT_RESPONSES || !strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") {
				http.ServeFile(writer, request, STATIC_CONTENT_DIR+string(os.PathSeparator)+request.URL.Path)
			} else {
				// SEE: https://gist.github.com/CJEnright/bc2d8b8dc0c1389a9feeddb110f822d7

				writer.Header().Set("Content-Encoding", "gzip")

				gz := gzPool.Get().(*gzip.Writer)
				defer gzPool.Put(gz)

				gz.Reset(writer)
				defer gz.Close()

				http.ServeFile(&gzipResponseWriter{ResponseWriter: writer, Writer: gz}, request, STATIC_CONTENT_DIR+string(os.PathSeparator)+request.URL.Path)
			}

		} else {
			writer.WriteHeader(http.StatusNotFound)
		}

	}
}

func processProxyRequest(theHandler *handler, proxyConfig *proxyconfig.ProxyMapping, writer http.ResponseWriter, request *http.Request) {
	proxyUrl := proxyUrlMap[proxyConfig.LocalPath]
	reverseProxy := reverseProxyMap[proxyConfig.LocalPath]

	request.URL.Host = proxyUrl.Host
	if proxyConfig.LocalPath != proxyConfig.RemotePath {
		var newPath string
		if proxyConfig.LocalPath == "/" {
			newPath = proxyConfig.RemotePath + request.URL.Path
		} else {
			newPath = proxyConfig.RemotePath + request.URL.Path[len(proxyConfig.LocalPath):]
		}
		request.URL.Path = newPath
	}
	request.URL.Scheme = proxyUrl.Scheme
	request.Header.Set("X-Forwarded-Host", request.Host)
	request.Header.Set("X-Forwarded-Port", fmt.Sprintf("%v", theHandler.port))
	request.Header.Set("X-Forwarded-Proto", theHandler.protocol)
	request.Host = proxyUrl.Host

	reverseProxy.ServeHTTP(writer, request)
}

func main() {
	var (
		version = flag.Bool("version", false, "Display version number, which by the way is "+VERSION)
		domains = flag.String("domains", "", "Comma delineated list of domains for which HTTPS requests should be accepted\nFor example, "+
			"-domains=yourdomain.com,www.yourdomain.com\n"+
			"Be sure your nameservers are pointing your domain(s) to this server's ip address.")
		simpleProxy = flag.String("simpleProxy", "",
			"[required HTTP/HTTPS]://[required HOSTNAME/IPADDRESS]:[optional port]\n"+""+
				"For example, -simpleProxy=https://yourdomain.com or -simpleHost=http://localhost:8080")
		staticDir = flag.String("staticDir", "", "Directory of static content to serve\nFor example, -staticDir=/path/to/static/content/dir\n"+
			"If -proxyConfigFile is specified, the request will first be checked against proxy mappings.\n"+
			"If no proxy mapping is found, then we attempt to serve the request from this static content.")
		proxyConfigFile = flag.String("proxyConfigFile", "", "JSON file containing the proxy mappings\nFor example, -proxyConfigFile=/path/to/proxy.config\nExamples files:\n"+
			`Proxy requests inbound to /proxy/api to /api on a different server via https.
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

Proxy requests inbound to / to / on localhost:8080 via http.  This is equivalent to -simpleProxy=http://localhost:8080.
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
`)

		readTimeoutInMs  = flag.Int("readTimeoutInMs", DEFAULT_READ_TIMEOUT_MS, "Socket read timeout in milliseconds\nFor example, -readTimeoutInMs=5000")
		writeTimeoutInMs = flag.Int("writeTimeoutInMs", DEFAULT_WRITE_TIMEOUT_MS, "Socket write timeout in milliseconds\nFor example, -writeTimeoutInMs=5000")
		idleTimeoutInMs  = flag.Int("idleTimeoutInMs", DEFAULT_IDLE_TIMEOUT_MS, "Socket idle timeout in milliseconds\nFor example, -idleTimeoutInMs=5000")

		httpPort  = flag.Int("httpPort", 80, "Port on which to receive HTTP requests\nFor example, -httpPort=8080")
		httpsPort = flag.Int("httpsPort", 443, "Port on which to receive HTTPS requests\nFor example, -httpsPort=4443")

		certCacheDir = flag.String("certCacheDir", "",
			"Directory where certificates are stored\nFor example, -certCacheDir=/path/to/cert/dir\nIf not specified, a directory will be created in /tmp.\n"+
				"IMPORTANT NOTE: If you use a temp directory, it may be deleted on machine reboot.\n"+
				"This could be important if your machine reboots frequently since Let's Encrypt is subject to rate limits.\n"+
				"See:  https://letsencrypt.org/docs/rate-limits/")

		serviceInstallationInstructions = flag.Bool("serviceInstallationInstructions", false, "Display instructions on how to set gossl up as a service using systemd (Linux only instructions)")

		cacheControlPublic = flag.Bool("cacheControlPublic", false, "Only used when serving static files.\n"+
			"For example, -cacheControlPublic\n"+
			"It indicates that the response can be cached by clients and other proxies.  "+
			"It cannot be used with -cacheControlPrivate.")

		cacheControlPrivate = flag.Bool("cacheControlPrivate", false, "Only used when serving static files.\n"+
			"For example, -cacheControlPrivate\n"+
			"It indicates that the response can be cached only by clients.  "+
			"It cannot be used with -cacheControlPublic.")

		cacheControlMaxAgeInSeconds = flag.Int("cacheControlMaxAgeInSeconds", 24*60*60,
			"Only used when serving static files.\nFor example, -cacheControlMaxAgeInSeconds=86400\nThe maxium time in seconds that the response can be cached.")

		dontGzipStaticResponse = flag.Bool("dontGzipStaticResponse", false, "Only used when serving static files.\n"+
			"For example, -dontGzipStaticResponse\n"+
			"By default, responses served from the static content directory WILL be gzipped.  This option turns that OFF.\nYou probably don't want this.")
	)

	flag.Parse()

	if *version {
		fmt.Println("version " + VERSION)
		fmt.Println("Use -help to see options.")
		return
	}

	if *serviceInstallationInstructions {
		showServiceInstallationInstructions()
		return
	}

	if *simpleProxy == "" && *staticDir == "" && *proxyConfigFile == "" {
		fmt.Println("version " + VERSION)
		fmt.Println("Use -help to see options.")
		fmt.Println("You must specify either -simpleProxy, -staticDir, or -proxyConfigFile.  -staticDir and -proxyConfigFile can be used together.")
		return
	}

	var err error

	if *simpleProxy != "" {

		if *staticDir != "" {
			log.Fatal("simpleProxy cannot be used with a static content directory")
		}

		if *proxyConfigFile != "" {
			log.Fatalf("simpleProxy cannot be used with an proxyConfigFile file")
		}

		s := strings.Split(strings.ToLower(strings.TrimSpace(*simpleProxy)), ":")
		if len(s) > 3 || len(s) < 2 {
			log.Fatal("Invalid value for simpleProxy.  Examples: https:yourdomain.com or http:localhost:8080")
		}

		var port int
		host := strings.TrimSpace(s[1])
		protocol := strings.TrimSpace(s[0])

		if !strings.HasPrefix(host, "//") {
			log.Fatalf("Invalid URL format for -simpleProxy.  Missing //")
		} else {
			host = strings.TrimSpace(host[2:])
		}

		if protocol == "http" {
			port = 80
		} else if protocol == "https" {
			port = 443
		} else {
			log.Fatalf("Invalid protocol: %v", protocol)
		}

		if len(s) == 3 {
			port, err = strconv.Atoi(s[2])

			if err != nil {
				log.Fatalf("Error parsing port: %v", err)
			}

			if port < 0 || port > 65535 {
				log.Fatalf("Port not in valid range (0-65535): %v", port)
			}
		}

		urlStr := fmt.Sprintf("%v://%v:%v", protocol, host, port)
		simpleProxyURL, err = url2.Parse(urlStr)

		if err != nil {
			log.Fatalf("Error parsing %v", urlStr)
		} else {
			simpleReverseProxy = httputil.NewSingleHostReverseProxy(simpleProxyURL)
		}
	}

	if *staticDir != "" {
		stats, err := os.Stat(*staticDir)

		if stats == nil || os.IsNotExist(err) {
			log.Fatalf("Static content directory %v doesn't exist", *staticDir)
		}

		if !stats.IsDir() {
			log.Fatalf("The path specified by staticdir (%v) is not a diretory", *staticDir)
		}

		if *cacheControlMaxAgeInSeconds < 0 {
			log.Printf("-cacheControlMaxAgeInSeconds must be non-negative")
		}

		if !*cacheControlPrivate && !*cacheControlPublic {
			log.Printf("Neither -cacheControlPrivate nor -cacheControlPublic were specified.  Defaulting to -cacheControlPrivate")
			*cacheControlPrivate = true
		} else if *cacheControlPublic && *cacheControlPrivate {
			log.Fatal("-cacheControlPublic and -cacheControlPrivate cannot BOTH be specified.  Pick one.")
		}

		CACHE_CONTROL_PRIVATE = *cacheControlPrivate
		CACHE_CONTROL_MAX_AGE_IN_SECONDS = *cacheControlMaxAgeInSeconds
		STATIC_CONTENT_DIR = *staticDir
		DONT_GZIP_STATIC_CONTENT_RESPONSES = *dontGzipStaticResponse
	}

	if *proxyConfigFile != "" {
		PROXY_CONFIG, err = proxyconfig.ReadProxyConfig(*proxyConfigFile)

		if err != nil {
			log.Fatal(err)
		}

		if PROXY_CONFIG != nil && len(PROXY_CONFIG.Mappings) > 0 {
			reverseProxyMap = make(map[string]*httputil.ReverseProxy)
			proxyUrlMap = make(map[string]*url2.URL)

			for _, proxyConfig := range PROXY_CONFIG.Mappings {

				if STATIC_CONTENT_DIR != "" && proxyConfig.LocalPath == "/" {
					log.Fatalf("A static content directory has been set.  This is not compatible with your proxy configuration file " +
						"because one of your proxy mappings is set to '/'")
				}

				var urlStr string
				if proxyConfig.UseHTTPS {
					urlStr = fmt.Sprintf("https://%v:%v", proxyConfig.Host, proxyConfig.Port)
				} else {
					urlStr = fmt.Sprintf("http://%v:%v", proxyConfig.Host, proxyConfig.Port)
				}

				url, err := url2.Parse(urlStr)
				if err != nil {
					log.Fatalf("Error parsing %v", urlStr)
				} else {
					proxyPath := proxyConfig.LocalPath
					reverseProxyMap[proxyPath] = httputil.NewSingleHostReverseProxy(url)
					proxyUrlMap[proxyPath] = url
				}
			}
		}
	}

	if *readTimeoutInMs < MIN_READ_TIMEOUT_MS {
		log.Fatalf("Invalid readTimeoutInMs.  Minimum value is %v ms", MIN_READ_TIMEOUT_MS)
	} else if *readTimeoutInMs > MAX_READ_TIMEOUT_MS {
		log.Fatalf("Invalid readTimeoutInMs.  Maximum value is %v ms", MAX_READ_TIMEOUT_MS)
	}

	if *writeTimeoutInMs < MIN_WRITE_TIMEOUT_MS {
		log.Fatalf("Invalid writeTimeoutInMs.  Minimum value is %v ms", MIN_WRITE_TIMEOUT_MS)
	} else if *writeTimeoutInMs > MAX_WRITE_TIMEOUT_MS {
		log.Fatalf("Invalid writeTimeoutInMs.  Maximum value is %v ms", MAX_WRITE_TIMEOUT_MS)
	}

	if *idleTimeoutInMs < MIN_IDLE_TIMEOUT_MS {
		log.Fatalf("Invalid idleTimeoutInMs.  Minimum value is %v ms", MIN_IDLE_TIMEOUT_MS)
	} else if *idleTimeoutInMs > MAX_IDLE_TIMEOUT_MS {
		log.Fatalf("Invalid idleTimeoutInMs.  Maximum value is %v ms", MAX_IDLE_TIMEOUT_MS)
	}

	if *httpsPort <= 0 {
		log.Fatalf("Invalid HTTPS port: %v", *httpsPort)
	}

	if *httpPort <= 0 {
		log.Fatalf("Invalid HTTP port: %v", *httpPort)
	}

	validDomains := make([]string, 0)

	if *domains != "" {
		s := strings.Split(*domains, ",")

		for _, domain := range s {
			d := strings.ToLower(strings.TrimSpace(domain))

			if len(d) > 0 {
				validDomains = append(validDomains, d)
			}
		}

		if len(validDomains) == 0 {
			log.Fatal("domains flag specified but no domains found")
		}
	}

	useHTTPS := (len(validDomains) > 0)

	if useHTTPS && *httpPort != 80 {
		log.Fatalf("Invalid configuration.  Autocert requires HTTP challenge requests to be received on port 80, not %v", *httpPort)
	}

	var certManager *autocert.Manager

	if useHTTPS {
		*certCacheDir = strings.TrimSpace(*certCacheDir)

		if *certCacheDir != "" {

			stats, err := os.Stat(*certCacheDir)

			if stats == nil || os.IsNotExist(err) {
				log.Fatalf("Certificate directory %v doesn't exist", *certCacheDir)
			}

			if !stats.IsDir() {
				log.Fatalf("The path specified by certCacheDir (%v) is not a diretory", *certCacheDir)
			}

			user, _ := user.Current()

			if runtime.GOOS != "windows" {
				if fmt.Sprintf("%v", stats.Mode()) != "drwx------" {
					log.Fatalf("The cache directory %v must not be readable by other users and must be readable, writeable, and executable by this user: %v",
						*certCacheDir, user.Username)
				}
			} else {
				log.Printf("WARNING: Ensure that the cache directory %v is not be readable by other users and is readable, writeable, and executable by this user: %v",
					*certCacheDir, user.Username)
			}

		} else {

			*certCacheDir = certificateCacheDir()

			if *certCacheDir == "" {
				log.Fatalf("Unable to create certificate cache directory")
			}
		}

		log.Printf("Using certificate cache directory: %v\n", *certCacheDir)

		if STATIC_CONTENT_DIR != "" {
			var cacheControlType string
			if CACHE_CONTROL_PRIVATE {
				cacheControlType = "private"
			} else {
				cacheControlType = "public"
			}

			log.Printf("Serving static files from directory %v with: Cache-Control=%v, max-age=%v",
				cacheControlType, CACHE_CONTROL_MAX_AGE_IN_SECONDS)
		}

		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(validDomains...),
			Cache:      autocert.DirCache(*certCacheDir),
		}

		httpsServer := &http.Server{
			Addr:    fmt.Sprintf(":%v", *httpsPort),
			Handler: &handler{protocol: "https", port: *httpsPort},
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
				MinVersion: tls.VersionTLS12,
			},
			ReadTimeout:  time.Duration(*readTimeoutInMs) * time.Millisecond,
			WriteTimeout: time.Duration(*writeTimeoutInMs) * time.Millisecond,
			IdleTimeout:  time.Duration(*idleTimeoutInMs) * time.Millisecond,
		}

		log.Printf("Server domains %v from port %v", validDomains, *httpsPort)

		go func() {
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("httpsServer.ListendAndServeTLS() failed with %s\n", err)
			}
		}()
	}

	var httpHander http.Handler

	if certManager != nil {
		// We need to wrap our handler so that we can accept challenges from Let's Encrypt
		httpHander = certManager.HTTPHandler(&handler{protocol: "http", port: *httpPort})
	} else {
		httpHander = &handler{protocol: "http", port: *httpPort}
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%v", *httpPort),
		Handler:      httpHander,
		ReadTimeout:  time.Duration(*readTimeoutInMs) * time.Millisecond,
		WriteTimeout: time.Duration(*writeTimeoutInMs) * time.Millisecond,
		IdleTimeout:  time.Duration(*idleTimeoutInMs) * time.Millisecond,
	}

	log.Printf("Serving static content from:%v\n", STATIC_CONTENT_DIR)
	log.Printf("Listening on HTTP port %v\n", *httpPort)
	if useHTTPS {
		log.Printf("Listening on HTTPS port %v\n", *httpsPort)
	}

	if len(proxyUrlMap) > 0 {
		for _, url := range proxyUrlMap {
			log.Printf("Serving proxy: %v", url)
		}
	}

	err = httpServer.ListenAndServe()

	if err != nil {
		log.Fatalf("httpServer.ListendAndServeTLS() failed with %s\n", err)
	}
}

// https://gist.github.com/samthor/5ff8cfac1f80b03dfe5a9be62b29d7f2
// cacheDir makes a consistent cache directory inside /tmp. Returns "" on error.
func certificateCacheDir() (dir string) {
	if u, _ := user.Current(); u != nil {
		dir = filepath.Join(os.TempDir(), "cache-golang-autocert-"+u.Username)
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	return ""
}

func showServiceInstallationInstructions() {
	instructions :=
		`
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

ExecStart=/path/to/gossl -simpleProxy=http://localhost:8080 -domains=mydomain.com,www.mydomain.com
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

If you update the service file, you'll need to do this:
> sudo systemctl stop myservice.service
> sudo systemctl daemon-reload
> sudo systemctl start myservice.service

To debug problems with starting the service:
>sudo systemctl status myservice.service

To see the service's current output (also useful for debugging):
> sudo journalctl -u myservice.service -f
`
	fmt.Println(instructions)
}

// See: https://gist.github.com/CJEnright/bc2d8b8dc0c1389a9feeddb110f822d7
var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(ioutil.Discard)
		return w
	},
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
