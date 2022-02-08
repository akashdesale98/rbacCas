package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"rbacCas/dbops"
	"rbacCas/models"
	"rbacCas/utils"
)

var err error

func Signup(w http.ResponseWriter, r *http.Request) {

	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n > 0 {
		log.Println("User already registered")
		w.Write([]byte("User already registered"))
		http.Error(w, "admin already registered", http.StatusForbidden)
		return
	}

	member.Password, err = utils.HashPassword(member.Password)
	if err != nil {
		log.Println("password hashing", err)
		w.Write([]byte("Error Occurred" + err.Error()))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// member.Privilage = "admin"

	_, err = dbops.InsertUser(&member)
	if err != nil {
		log.Println("signing up user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	w.Write([]byte("User can log in now"))
}

func Signin(w http.ResponseWriter, r *http.Request) {

	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n < 1 {
		log.Println("User not registered")
		w.Write([]byte("User not registered"))
		http.Error(w, "User not registered", http.StatusForbidden)
		return
	}

	user, err := dbops.FetchUser(member.Username)
	if err != nil {
		log.Println("FetchUser user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	ok := utils.CheckPasswordHash(member.Password, user[0].Password)
	if !ok {
		log.Println("Password is wrong")
		w.Write([]byte("Password is wrong"))
		http.Error(w, "Password is wrong", http.StatusForbidden)
		return
	}
	token, err := utils.CreateToken(user[0])
	if !ok {
		log.Println("CreateToken error", err)
		w.Write([]byte("CreateToken error" + err.Error()))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	user[0].Token = token

	json.NewEncoder(w).Encode(user[0])
}
