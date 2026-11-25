package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	certFile := flag.String("ca-cert", "ca.pem", "PEM file containing the CA certificate")
	keyFile := flag.String("ca-key", "key.pem", "PEM file containing the CA private key")
	flag.Parse()

	cert, err := goproxy.LoadOrCreateCA(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(customAlwaysMitm)
	proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
