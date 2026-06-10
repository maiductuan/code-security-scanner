package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
)

const (
	// Hardcoded credentials (vulnerable to SEC-SEC-001)
	awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
	awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Path Traversal (vulnerable to security/path-traversal)
	data, err := ioutil.ReadFile(filepath.Join("public", filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, string(data))
}

func main() {
	http.HandleFunc("/file", fileHandler)
	http.ListenAndServe(":8080", nil)
}
