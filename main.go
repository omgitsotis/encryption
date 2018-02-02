package main

import (
  "fmt"
  "io/ioutil"
  "log"
  "net/http"
  "github.com/gorilla/mux"
  "github.com/omgitsotis/encryption/client"
  "encoding/base64"
)

var encryptClient client.EncryptionClient

func main() {
	encryptClient.Storage = make(map[string][]byte, 0)
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/retrieve/{id}", getEncrypted).Methods("POST")
	router.HandleFunc("/store/{id}", storeEncrypted).Methods("POST")

	http.Handle("/", router)
	log.Println("Running server")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func storeEncrypted(w http.ResponseWriter, r *http.Request) {  	
	vars := mux.Vars(r)
	id := vars["id"]

  	payload, err := ioutil.ReadAll(r.Body)
  	if err != nil || string(payload) == "" {
    	WriteHTTPOutput(w, 422, "The request body was empty or unprocessable")
    	return
  	}

  	fmt.Println("\n\nPayload: ", string(payload))
  	
  	privateKey, err := encryptClient.Store([]byte(id), payload)
  	if err != nil {
  		WriteHTTPOutput(w, 400, "error encrypting text: " + err.Error())
  		return
  	}
  	
  	WriteHTTPOutput(w, 200, base64.StdEncoding.EncodeToString(privateKey))
}

func getEncrypted(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	key, err := ioutil.ReadAll(r.Body)
  	if err != nil || string(key) == "" {
    	WriteHTTPOutput(w, 422, "The request body was empty or unprocessable")
    	return
  	}

  	decodedKey, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil {
		fmt.Println(err.Error())
		WriteHTTPOutput(w, 400, "error decoding key: " + err.Error())
		return
	}

  	payload, err := encryptClient.Retrieve([]byte(id), decodedKey)
  	if err != nil || string(payload) == "" {
    	fmt.Println(err.Error())
    	WriteHTTPOutput(w, 400, "error decrypting text: " + err.Error())
    	return
  	}

  	WriteHTTPOutput(w, 200, string(payload))
}

func WriteHTTPOutput(w http.ResponseWriter, status int, message string) {
  w.WriteHeader(status)
  log.Println(message)
  fmt.Fprintf(w, message)
}

