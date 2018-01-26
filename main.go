package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type ProxyHandler struct{}

type ClientRequest struct {
	method  string
	url     url.URL
	tls     bool
	request *http.Request
	reader  *bufio.Reader
	writer  *bufio.Writer
	conn    net.Conn
}

type ServerResponse struct {
	request *ClientRequest
	reader  *bufio.Reader
	writer  *bufio.Writer
	conn    net.Conn
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
		c.request.Header.Set("Host", hostParts[0])
	} else {
		c.request.Header.Set("Host", c.url.Host)
	}

	var conn net.Conn
	var err error
	if c.tls {
		config := tls.Config{InsecureSkipVerify: true}
		conn, err = tls.Dial("tcp", c.url.Host, &config)
		if err != nil {
			sendError(c, fmt.Sprintln("Unable to make tls connection", err), http.StatusInternalServerError)
			return nil, err
		}
	} else {
		conn, err = net.Dial("tcp", c.url.Host)
		if err != nil {
			sendError(c, fmt.Sprintln("Unable to make connection", err), http.StatusInternalServerError)
			return nil, err
		}
	}
	s = &ServerResponse{conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
	defer s.conn.Close()

	log.Printf("%s - - \"%s %s %s\"", c.url.Host, c.method, c.url.RequestURI(), c.request.Proto)

	// Write request to the server
	io.WriteString(s.writer, fmt.Sprintf("%s %s HTTP/1.1\r\n", c.method, c.url.RequestURI()))
	c.request.Header.Write(s.writer)
	s.writer.Write([]byte("\r\n"))
	s.writer.Flush()

	if c.request.Header.Get("Upgrade") != "" {
		log.Println("[!] Unsupported upgrade!")
	} else {
		body, err := ioutil.ReadAll(c.request.Body)
		if err != nil {
			sendError(c, fmt.Sprintln("Unable to read response body", err), http.StatusInternalServerError)
			return nil, err
		}
		s.writer.Write(body)
		s.writer.Flush()
	}

	response, err := http.ReadResponse(s.reader, c.request)
	if err != nil {
		sendError(c, fmt.Sprintln("Unable to read response headers", err), http.StatusInternalServerError)
		return nil, err
	}

	// Write response to the client
	io.WriteString(c.writer, fmt.Sprintf("HTTP/1.1 %s\r\n", response.Status))
	response.Header.Write(c.writer)
	io.WriteString(c.writer, "\r\n")
	c.writer.Flush()

	buf := make([]byte, 0, 4096)
	for {
		n, err := response.Body.Read(buf[0:4096])
		if n > 0 {
			c.writer.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Println(err)
				return nil, err
			}
		}
	}
	c.writer.Flush()

	return s, nil
}

func prepareResponseHeaders(dst, src http.Header) {
	badHeaders := map[string]bool{"Content-Length": true, "Connection": true}
	for k, _ := range dst {
		dst.Del(k)
	}

	for k, vs := range src {
		if _, ok := badHeaders[k]; ok {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}

	dst.Set("Connection", "Close")
}

func (h ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "CONNECT":
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

		// s, _ := bufio.NewReader(rawClientTls).Peek(700)
		// fmt.Println(string(s))
		reader := bufio.NewReader(rawClientTls)
		writer := bufio.NewWriter(rawClientTls)
		tlsr, err := http.ReadRequest(reader)
		if err != nil {
			log.Printf("Cannot read tls request %v %v", r.Host, err)
			return
		}

		req := ClientRequest{
			method:  tlsr.Method,
			url:     url.URL{"https", "", nil, r.URL.Host, tlsr.URL.Path, tlsr.URL.RawPath, tlsr.URL.ForceQuery, tlsr.URL.RawQuery, tlsr.URL.Fragment},
			tls:     true,
			request: tlsr,
			reader:  reader,
			writer:  writer,
			conn:    conn,
		}

		makeRequest(&req)
	default:
		if !r.URL.IsAbs() {
			http.Error(w, fmt.Sprintf("%s method requires absolute URL", r.Method), http.StatusInternalServerError)
			return
		}

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

		// Add the port if it is missing from the url.Host
		host := r.URL.Host
		matched, err := regexp.MatchString(":[0-9]+", host)
		if !matched {
			host += ":80"
		}

		c := ClientRequest{
			method:  r.Method,
			url:     url.URL{"http", "", nil, host, r.URL.Path, r.URL.RawPath, r.URL.ForceQuery, r.URL.RawQuery, r.URL.Fragment},
			tls:     false,
			request: r,
			reader:  bufrw.Reader,
			writer:  bufrw.Writer,
			conn:    conn,
		}

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
		Handler:      ProxyHandler{},
	}

	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.Printf("Alloc = %v\tTotalAlloc = %v\tSys = %v\tNumGC = %v\t Routines = %v\n", m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC, runtime.NumGoroutine())
			time.Sleep(5 * time.Second)
		}
	}()

	srv.ListenAndServe()
}
