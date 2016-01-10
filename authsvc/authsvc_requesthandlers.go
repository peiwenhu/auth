package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/peiwenhu/auth/auth"
	"github.com/peiwenhu/auth/client"
)

type RequestProcessor struct {
	authenticator    *auth.Authenticator
	userdbAccessor   auth.UserDb_I
	clientdbAccessor client.ClientDb_I
}

func NewRequestProcessor(
	au *auth.Authenticator, userdb auth.UserDb_I, clientdb client.ClientDb_I) *RequestProcessor {
	return &RequestProcessor{authenticator: au, userdbAccessor: userdb, clientdbAccessor: clientdb}
}

func (rp RequestProcessor) createUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("got createUser request")

	userid := r.PostFormValue("userid")
	if userid == "" {
		log.Println("received blank userid")
		writeJsonError(w, apiError{err: ErrInternal, code: http.StatusBadRequest})
		return
	}
	password := r.FormValue("password")
	if password == "" {
		log.Println("received blank password")
		writeJsonError(w, apiError{err: ErrInternal, code: http.StatusBadRequest})
		return
	}

	clientId := r.FormValue("clientid")
	clientSecret := r.FormValue("client_secret")
	clientInfo := client.NewClient(clientId, clientSecret)

	if err := rp.clientdbAccessor.VerifyClient(*clientInfo); err != nil {
		writeJsonError(w, apiError{err: err, code: http.StatusBadRequest})
		return
	}

	username := r.FormValue("username")

	if username == "" {
		log.Println("received blank username")
		writeJsonError(w, apiError{err: fmt.Errorf("Username can not be empty"), code: http.StatusBadRequest})
		return
	}
	userlang := r.FormValue("lang")
	if userlang == "" {
		log.Println("received blank lang str")
		writeJsonError(w, apiError{err: ErrInternal, code: http.StatusBadRequest})
		return
	}

	//user cred
	otherFields := make(map[auth.UserFieldName]interface{})
	otherFields[auth.UserField_Language] = userlang
	accessToken, refreshToken, err := rp.authenticator.CreateUser(
		userid, username, []byte(password), otherFields, rp.userdbAccessor)

	if err != nil {
		switch err {
		case auth.ErrUserExists, auth.ErrUserIdInvalid, auth.ErrUserIdForbidden:
			writeJsonError(w, apiError{err: err, code: http.StatusBadRequest})
		default:
			log.Printf("failed to create user:%v", err)
			writeJsonError(w, apiError{err: ErrInternal, code: http.StatusInternalServerError})
		}

		return
	}
	//write good response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var res struct {
		AccessToken  string `json:access_token`
		RefreshToken string `json:refresh_token`
	}
	res.AccessToken = *accessToken
	res.RefreshToken = *refreshToken

	if err := json.NewEncoder(w).Encode(res); err != nil {
		panic(err)
	}
}

func writeJsonError(w http.ResponseWriter, err apiError) {
	w.WriteHeader(err.code)
	fmt.Fprintf(w, `{"error":%q}`, err.err.Error())
}
