package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	
	// Safe: cleaning path and verifying it stays inside target directory
	cleanPath := filepath.Clean(filename)
	if strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	
	data, err := ioutil.ReadFile(filepath.Join("public", cleanPath))
	if err != nil {
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, string(data))
}

func main() {
	// Safe: Reading credentials from environment
	awsKey := os.Getenv("AWS_ACCESS_KEY_ID")
	if awsKey == "" {
		fmt.Println("Warning: AWS Key not set in environment")
	}
	
	http.HandleFunc("/file", fileHandler)
	http.ListenAndServe(":8080", nil)
}
