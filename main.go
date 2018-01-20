package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

func blake2bsum(size int, data string) string {
	h, _ := blake2b.New(size, nil)
	fmt.Println(h.Size())
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

type helloHandler struct{}

type ClientRequest struct {
	method  string
	url     url.URL
	tls     bool
	headers http.Header
	reader  io.Reader
	writer  io.Writer
	conn    net.Conn
}

type ServerResponse struct {
	request *ClientRequest
	reader  io.Reader
	writer  io.Writer
	conn    net.Conn
}

// func MiddleWare(h http.Handler) http.Handler {
// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("[%d] %s - %s", getGID(), r.Method, r.URL.Path)
// 		defer log.Printf("[%d] %s - %s", getGID(), r.Method, r.URL.Path)
//
// 		h.ServeHTTP(w, r)
// 	})
//
// 	return handler
// }

type Error string

func (e Error) Error() string {
	return string(e)
}

func sendError(c *ClientRequest, message string, code int) {
	headers := make(http.Header)
	headers.Set("Connection", "Close")
	headers.Set("Content-Type", "text/plain; charset=utf-8")

	io.WriteString(c.writer, fmt.Sprintf("HTTP/1.1 %d Error\r\n", code))
	http.Header(headers).Write(c.writer)

	io.WriteString(c.writer, "\r\n")
	io.WriteString(c.writer, message)
}

func makeRequest(c *ClientRequest) (*ServerResponse, error) {
	var s *ServerResponse = nil

	// Need to re-set the Host header, for some reason it is removed from the client request
	hostParts := strings.Split(c.url.Host, ":")
	if hostParts[1] == "80" || hostParts[1] == "443" {
		c.headers.Set("Host", hostParts[0])
	} else {
		c.headers.Set("Host", c.url.Host)
	}

	log.Println(c.headers.Get("Host"))

	if c.tls {
		config := tls.Config{InsecureSkipVerify: true}
		conn, err := tls.Dial("tcp", c.url.Host, &config)
		if err != nil {
			sendError(c, fmt.Sprintln("Unable to make tls connection", err), http.StatusInternalServerError)
			return nil, err
		}
		s = &ServerResponse{conn: conn, reader: conn, writer: conn}
	} else {
		conn, err := net.Dial("tcp", c.url.Host)
		if err != nil {
			sendError(c, fmt.Sprintln("Unable to make connection", err), http.StatusInternalServerError)
			return nil, err
		}
		s = &ServerResponse{conn: conn, reader: conn, writer: conn}
	}
	defer s.conn.Close()

	io.WriteString(s.writer, fmt.Sprintf("%s %s HTTP/1.1\r\n", c.method, c.url.RequestURI()))
	c.headers.Write(s.writer)
	s.writer.Write([]byte("\r\n"))

	response, err := http.ReadResponse(bufio.NewReader(s.reader), nil)
	if err != nil {
		sendError(c, fmt.Sprintln("Unable to read response headers", err), http.StatusInternalServerError)
		return nil, err
	}

	io.WriteString(c.writer, fmt.Sprintf("HTTP/1.1 %d %s\r\n", response.StatusCode, response.Status))
	response.Header.Write(c.writer)
	io.WriteString(c.writer, "\r\n")

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		sendError(c, fmt.Sprintln("Unable to read response body", err), http.StatusInternalServerError)
		return nil, err
	}

	c.writer.Write(contents)
	return s, nil
}

func prepareResponseHeaders(dst, src http.Header) {
	badHeaders := map[string]bool{"Content-Length": true, "Connection": true}
	for k, _ := range dst {
		dst.Del(k)
	}

	for k, vs := range src {
		if _, ok := badHeaders[k]; ok {
			log.Printf("Skipping header %s\n", k)
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}

	dst.Set("Connection", "Close")
}

func (h helloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// log.Println(fmt.Sprintf("Connection %v %v", w, r))

	switch r.Method {

	case "CONNECT":
		// log.Println("CONNECT")
		// https: //golang.org/pkg/net/http/#Hijacker
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		bufrw.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
		bufrw.Flush()

		// https://golang.org/pkg/crypto/tls/#Server
		config := &tls.Config{
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return getCertificateHook(r.URL.Hostname(), clientHello)
			},
			InsecureSkipVerify: true,
		}

		rawClientTls := tls.Server(conn, config)
		defer rawClientTls.Close()

		if err := rawClientTls.Handshake(); err != nil {
			log.Printf("Cannot handshake client %v %v", r.Host, err)
			return
		}

		clientTlsReader := bufio.NewReader(rawClientTls)
		tlsr, err := http.ReadRequest(clientTlsReader)
		if err != nil {
			log.Printf("Cannot read tls request %v %v", r.Host, err)
			return
		}

		req := ClientRequest{
			"GET",
			url.URL{"https", "", nil, r.URL.Host, tlsr.URL.Path, tlsr.URL.RawPath, tlsr.URL.ForceQuery, tlsr.URL.RawQuery, tlsr.URL.Fragment},
			true,
			tlsr.Header,
			rawClientTls,
			rawClientTls,
			conn,
		}

		makeRequest(&req)
	default:
		// log.Println(r.Method)
		if !r.URL.IsAbs() {
			http.Error(w, fmt.Sprintf("%s method requires absolute URL", r.Method), http.StatusInternalServerError)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Add the port if it is missing from the url.Host
		host := r.URL.Host
		matched, err := regexp.MatchString(":[0-9]+", host)
		if !matched {
			host += ":80"
		}

		c := ClientRequest{
			r.Method,
			url.URL{"http", "", nil, host, r.URL.Path, r.URL.RawPath, r.URL.ForceQuery, r.URL.RawQuery, r.URL.Fragment},
			false,
			r.Header,
			conn, // Use conn for reader / writer to prevent having to flush all the time
			conn,
			conn,
		}

		// req := Req{*r.URL, bufrw, conn}
		makeRequest(&c)
		// fmt.Printf("Response: %v %v\n", s, err)
	}
}

func main() {
	srv := &http.Server{
		Addr:         "127.0.0.1:8001",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      helloHandler{},
	}

	log.Println(srv.ListenAndServe())
}
