package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/twocanoes/psso-server/pkg/constants"
	"github.com/twocanoes/psso-server/pkg/handlers"
)

func NewRouter() *http.ServeMux {
	// Create router and define routes and return that router
	router := http.NewServeMux()

	// well-knowns
	router.HandleFunc(constants.EndpointJWKS, handlers.WellKnownJWKS())
	router.HandleFunc(constants.EndpointAppleSiteAssoc, handlers.WellKnownAASA())

	// endpoints
	router.HandleFunc(constants.EndpointNonce, handlers.Nonce())
	router.HandleFunc(constants.EndpointRegister, handlers.Register())
	router.HandleFunc(constants.EndpointToken, handlers.Token())

	return router
}

func run() {

	if constants.Issuer == "" {
		log.Printf("Issuer is not defined! Set environment variable PSSO_ISSUER that matches your issuer in the PSSO extension")
		os.Exit(-1)
	}
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Define server options
	server := &http.Server{
		Addr:         constants.Address,
		Handler:      NewRouter(),
		TLSConfig:    cfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Handle ctrl+c/ctrl+x interrupt
	signal.Notify(runChan, os.Interrupt)

	// Alert the user that the server is starting
	log.Printf("Server is starting on %s\n", server.Addr)

	// Run the server on a new goroutine
	go func() {
		if err := server.ListenAndServeTLS(constants.TLSCertificateChainPath, constants.TLSPrivateKeyPath); err != nil {

			if err == http.ErrServerClosed {
				// Normal interrupt operation, ignore
			} else {
				log.Fatalf("Server failed to start due to err: %v", err)
			}
		}
	}()

	// Block on this channel listeninf for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interrupt := <-runChan

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30,
	)
	defer cancel()

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	log.Printf("Server is shutting down due to %+v\n", interrupt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}

func main() {

	// set up handlers

	handlers.CheckWellKnowns()

	run()

}
