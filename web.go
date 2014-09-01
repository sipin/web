// Package web is a lightweight web framework for Go. It's ideal for
// writing simple, performant backend web services.
package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/go.net/websocket"
)

// A Context object is created for every incoming HTTP request, and is
// passed to handlers as an optional first argument. It provides information
// about the request, including the http.Request object, the GET and POST params,
// and acts as a Writer for the response.
type Context struct {
	Request     *http.Request
	Params      map[string]string
	Data        map[string][]string
	DynamicData map[string]interface{}
	Server      *Server
	http.ResponseWriter
	flash          *Flash
	SessionStorage ISessionStorage
	XSRFToken      string
}

// WriteString writes string data into the response object.
func (ctx *Context) WriteString(content string) {
	ctx.ResponseWriter.Write([]byte(content))
}

// Abort is a helper method that sends an HTTP header and an optional
// body. It is useful for returning 4xx or 5xx errors.
// Once it has been called, any return value from the handler will
// not be written to the response.
func (ctx *Context) Abort(status int, body string) {
	ctx.ResponseWriter.WriteHeader(status)
	ctx.ResponseWriter.Write([]byte(body))
}

// Redirect is a helper method for 3xx redirects.
func (ctx *Context) Redirect(url_ string) {
	ctx.ResponseWriter.Header().Set("Location", url_)
	ctx.ResponseWriter.WriteHeader(302)
	ctx.ResponseWriter.Write([]byte("Redirecting to: " + url_))
}

func (ctx *Context) RedirectWithStatus(status int, url_ string) {
	ctx.ResponseWriter.Header().Set("Location", url_)
	ctx.ResponseWriter.WriteHeader(status)
	ctx.ResponseWriter.Write([]byte("Redirecting to: " + url_))
}

// Notmodified writes a 304 HTTP response
func (ctx *Context) NotModified() {
	ctx.ResponseWriter.WriteHeader(304)
}

// NotFound writes a 404 HTTP response
func (ctx *Context) NotFound(message string) {
	ctx.ResponseWriter.WriteHeader(404)
	ctx.ResponseWriter.Write([]byte(message))
}

//Unauthorized writes a 401 HTTP response
func (ctx *Context) Unauthorized() {
	ctx.ResponseWriter.WriteHeader(401)
}

//Forbidden writes a 403 HTTP response
func (ctx *Context) Forbidden() {
	ctx.ResponseWriter.WriteHeader(403)
}

// ContentType sets the Content-Type header for an HTTP response.
// For example, ctx.ContentType("json") sets the content-type to "application/json"
// If the supplied value contains a slash (/) it is set as the Content-Type
// verbatim. The return value is the content type as it was
// set, or an empty string if none was found.
func (ctx *Context) ContentType(val string) string {
	var ctype string
	if strings.ContainsRune(val, '/') {
		ctype = val
	} else {
		if !strings.HasPrefix(val, ".") {
			val = "." + val
		}
		ctype = mime.TypeByExtension(val)
	}
	if ctype != "" {
		ctx.Header().Set("Content-Type", ctype)
	}
	return ctype
}

// SetHeader sets a response header. If `unique` is true, the current value
// of that header will be overwritten . If false, it will be appended.
func (ctx *Context) SetHeader(hdr string, val string, unique bool) {
	if unique {
		ctx.Header().Set(hdr, val)
	} else {
		ctx.Header().Add(hdr, val)
	}
}

// SetCookie adds a cookie header to the response.
func (ctx *Context) SetCookie(cookie *http.Cookie) {
	ctx.Request.AddCookie(cookie)
	ctx.SetHeader("Set-Cookie", cookie.String(), false)
}

func (ctx *Context) AddDynamicData(key string, value interface{}) {
	if ctx.DynamicData == nil {
		ctx.DynamicData = make(map[string]interface{})
	}

	ctx.DynamicData[key] = value
}

func (ctx *Context) GetDynamicData(key string) interface{} {
	if ctx.DynamicData == nil {
		return nil
	}

	return ctx.DynamicData[key]
}

func (ctx *Context) AddDataUnique(dataType string, values ...string) {
	var data []string
	var ok bool
	if ctx.Data == nil {
		ctx.Data = make(map[string][]string)
	}

	if data, ok = ctx.Data[dataType]; !ok {
		data = []string{}
	}

	for _, val := range values {
		isNewVal := true
		for _, ele := range data {
			if ele == val {
				isNewVal = false
			}
		}

		if isNewVal {
			data = append(data, val)
		}
	}
	ctx.Data[dataType] = data
}

func (ctx *Context) GetData(dataType string) (values []string) {
	return ctx.Data[dataType]
}

func (ctx *Context) AddJS(val ...string) {
	ctx.AddDataUnique("js", val...)
}

func (ctx *Context) GetJS() (values []string) {
	return ctx.GetData("js")
}

func (ctx *Context) AddCSS(val ...string) {
	ctx.AddDataUnique("css", val...)
}

func (ctx *Context) GetCSS() (values []string) {
	return ctx.GetData("css")
}

func (ctx *Context) GetDefaultStaticDirs() []string {
	return defaultStaticDirs
}

func (ctx *Context) GetIP() (ip string) {
	host, _, _ := net.SplitHostPort(ctx.Request.RemoteAddr)
	return host
}

func (ctx *Context) getStaticFileHash(name string) string {
	if ctx.Server.Config.StaticDir != "" {
		staticFile := path.Join(ctx.Server.Config.StaticDir, name)
		if fileExists(staticFile) {
			data, err := ioutil.ReadFile(staticFile)
			if err != nil {
				return ""
			}
			return fmt.Sprintf("%x", md5.Sum(data))
		}
	} else {
		for _, staticDir := range defaultStaticDirs {
			staticFile := path.Join(staticDir, name)
			if fileExists(staticFile) {
				data, err := ioutil.ReadFile(staticFile)
				if err != nil {
					return ""
				}
				return fmt.Sprintf("%x", md5.Sum(data))
			}
		}
	}
	return ""
}

func isIE(version, user_agent string) bool {
	key := "MSIE " + version
	return strings.Contains(user_agent, key)
}

var browserMatchMap = map[string]func(user_agent string) bool{
	"ie8": func(user_agent string) bool { return isIE("8.0", user_agent) },
	"ie9": func(user_agent string) bool { return isIE("9.0", user_agent) },
}

func browserMatch(t, user_agent string) bool {
	if user_agent == "" {
		return false
	}
	if t == "" {
		return true
	}
	handler, ok := browserMatchMap[t]
	if !ok {
		return false
	}
	return handler(user_agent)
}

func splitExclude(s string) (t, v string) {
	if !strings.Contains(s, ":") {
		return "", s
	}
	ss := strings.Split(s, ":")
	return ss[0], ss[1]
}

func (ctx *Context) getUserAgent() string {
	agents := ctx.Request.Header["User-Agent"]
	if len(agents) > 0 {
		return agents[0]
	}
	return ""
}

func (ctx *Context) IsExcludeType(url string) bool {
	types := strings.Split(ctx.Server.Config.StaticHostExcludeType, ",")
	for _, t := range types {
		if t == "" {
			continue
		}
		t1, v := splitExclude(t)
		if browserMatch(t1, ctx.getUserAgent()) && strings.HasSuffix(url, v) {
			return true
		}
	}
	return false
}

func (ctx *Context) IsExcludeFile(url string) bool {
	files := strings.Split(ctx.Server.Config.StaticHostExcludeFile, ",")
	for _, f := range files {
		if f == "" {
			continue
		}
		t1, v := splitExclude(f)
		if browserMatch(t1, ctx.getUserAgent()) && url == v {
			return true
		}
	}
	return false
}

func (ctx *Context) GetStaticUrl(url string) string {
	if url[0] != '/' {
		return url
	}
	if ctx.Server.Config.StaticHost == "" {
		return url
	}

	if ctx.IsExcludeFile(url) {
		return url
	}

	if ctx.IsExcludeType(url) {
		return url
	}

	hash := ctx.getStaticFileHash(url)

	if hash == "" {
		return ctx.Server.Config.StaticHost + url
	}

	if ctx.Server.Config.StaticHost == "/" {
		return url + "?hash=" + hash
	}
	return ctx.Server.Config.StaticHost + url + "?hash=" + hash
}

func getCookieSig(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}

func (ctx *Context) SetSecureCookie(name string, val string, age int64) {
	//base64 encode the val
	if len(ctx.Server.Config.CookieSecret) == 0 {
		ctx.Server.Logger.Println("Secret Key for secure cookies has not been set. Please assign a cookie secret to web.Config.CookieSecret.")
		return
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(val))
	encoder.Close()
	vs := buf.String()
	vb := buf.Bytes()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getCookieSig(ctx.Server.Config.CookieSecret, vb, timestamp)
	cookie := strings.Join([]string{vs, timestamp, sig}, "|")
	ctx.SetCookie(NewCookie(name, cookie, age))
}

func (ctx *Context) GetSecureCookie(name string) (string, bool) {
	for _, cookie := range ctx.Request.Cookies() {
		if cookie.Name != name {
			continue
		}

		parts := strings.SplitN(cookie.Value, "|", 3)
		if len(parts) < 3 {
			return "", false
		}

		val := parts[0]
		timestamp := parts[1]
		sig := parts[2]

		if getCookieSig(ctx.Server.Config.CookieSecret, []byte(val), timestamp) != sig {
			return "", false
		}

		ts, _ := strconv.ParseInt(timestamp, 0, 64)

		if time.Now().Unix()-31*86400 > ts {
			return "", false
		}

		buf := bytes.NewBufferString(val)
		encoder := base64.NewDecoder(base64.StdEncoding, buf)

		res, _ := ioutil.ReadAll(encoder)
		return string(res), true
	}
	return "", false
}

func (ctx *Context) RemoveCookie(name string) {
	ctx.SetCookie(NewCookie(name, "", -1))
}

// small optimization: cache the context type instead of repeteadly calling reflect.Typeof
var contextType reflect.Type

var defaultStaticDirs []string

func init() {
	contextType = reflect.TypeOf(Context{})
	//find the location of the exe file
	wd, _ := os.Getwd()
	arg0 := path.Clean(os.Args[0])
	var exeFile string
	if strings.HasPrefix(arg0, "/") {
		exeFile = arg0
	} else {
		//TODO for robustness, search each directory in $PATH
		exeFile = path.Join(wd, arg0)
	}
	parent, _ := path.Split(exeFile)
	defaultStaticDirs = append(defaultStaticDirs, path.Join(parent, "static"))
	defaultStaticDirs = append(defaultStaticDirs, path.Join(wd, "static"))
	return
}

// Process invokes the main server's routing system.
func Process(c http.ResponseWriter, req *http.Request) {
	mainServer.Process(c, req)
}

// Run starts the web application and serves HTTP requests for the main server.
func Run(addr string) {
	mainServer.Run(addr)
}

// RunTLS starts the web application and serves HTTPS requests for the main server.
func RunTLS(addr string, config *tls.Config) {
	mainServer.RunTLS(addr, config)
}

// RunScgi starts the web application and serves SCGI requests for the main server.
func RunScgi(addr string) {
	mainServer.RunScgi(addr)
}

// RunFcgi starts the web application and serves FastCGI requests for the main server.
func RunFcgi(addr string) {
	mainServer.RunFcgi(addr)
}

// Close stops the main server.
func Close() {
	mainServer.Close()
}

// Get adds a handler for the 'GET' http method in the main server.
func Get(route string, handler interface{}) {
	mainServer.Get(route, handler)
}

// Post adds a handler for the 'POST' http method in the main server.
func Post(route string, handler interface{}) {
	mainServer.addRoute(route, "POST", handler)
}

// Put adds a handler for the 'PUT' http method in the main server.
func Put(route string, handler interface{}) {
	mainServer.addRoute(route, "PUT", handler)
}

// Delete adds a handler for the 'DELETE' http method in the main server.
func Delete(route string, handler interface{}) {
	mainServer.addRoute(route, "DELETE", handler)
}

// Match adds a handler for an arbitrary http method in the main server.
func Match(method string, route string, handler interface{}) {
	mainServer.addRoute(route, method, handler)
}

//Adds a custom handler. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
func Handler(route string, method string, httpHandler http.Handler) {
	mainServer.Handler(route, method, httpHandler)
}

//Adds a handler for websockets. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
func Websocket(route string, httpHandler websocket.Handler) {
	mainServer.Websocket(route, httpHandler)
}

// SetLogger sets the logger for the main server.
func SetLogger(logger *log.Logger) {
	mainServer.Logger = logger
}

// SetLogger sets the logger for the main server.
func SetSessionStorage(ss ISessionStorage) {
	mainServer.SessionStorage = ss
}

func SetXSRFOption(getUid func(*Context) string) {
	mainServer.XSRFGetUid = getUid
	mainServer.enableXSRF = true
}

func SetErrorHandler(f func(errorMsg string)) {
	mainServer.ErrorHandler = f
}

func SetErrorPageHandler(f func(*Context, int, interface{}) string) {
	mainServer.ErrorPageHandler = f
}

// Config is the configuration of the main server.
var Config = &ServerConfig{
	RecoverPanic: true,
}

var mainServer = NewServer()
