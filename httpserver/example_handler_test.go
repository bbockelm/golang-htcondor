package httpserver_test

import (
	"log"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver"
)

// ExampleNewHandler demonstrates how to create an HTTP handler that can be embedded
// in a custom HTTP server.
func ExampleNewHandler() {
	// Create a collector (optional, for discovery and metrics)
	collector := htcondor.NewCollector("collector.example.com:9618")

	// Create a handler with your configuration
	handler, err := httpserver.NewHandler(httpserver.HandlerConfig{
		ScheddName: "my-schedd",
		ScheddAddr: "schedd.example.com:9618",
		Collector:  collector,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Embed the handler in your own HTTP server
	// You can add your own routes and middleware
	mux := http.NewServeMux()
	
	// Add your custom routes
	mux.HandleFunc("/custom", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Custom endpoint"))
	})
	
	// Mount the HTCondor handler under a prefix
	mux.Handle("/condor/", http.StripPrefix("/condor", handler))
	
	// Create your HTTP server with custom settings
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start serving
	log.Printf("Server listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
