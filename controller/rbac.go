package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"rbacCas/dbops"
	"rbacCas/models"
	"rbacCas/utils"
)

func AddUser(w http.ResponseWriter, r *http.Request) {
	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n > 0 {
		log.Println("User already exist")
		w.Write([]byte("User already exist"))
	}

	member.Password, err = utils.HashPassword(member.Password)
	if err != nil {
		log.Println("password hashing", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	if member.Privilage == "" {
		log.Println("Privilage empty")
		w.Write([]byte("Privilage empty"))
	}

	// if n == 0 {
	// 	member.Privilage = "admin"
	// } else {
	// 	member.Privilage = "Viewer"
	// }

	_, err = dbops.InsertUser(&member)
	if err != nil {
		log.Println("signing up user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	w.Write([]byte("User Added"))
}

func RemoveUser(w http.ResponseWriter, r *http.Request) {
	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n < 1 {
		log.Println("User does not exist")
		w.Write([]byte("User does not exist"))
	}

	_, err = dbops.DeleteUser(member.Username)
	if err != nil {
		log.Println("deleting user", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	w.Write([]byte("User Added"))
}

func ChangeRoles(w http.ResponseWriter, r *http.Request) {
	var member models.Members
	json.NewDecoder(r.Body).Decode(&member)

	n := dbops.CheckUser(member.Username)
	if n < 1 {
		log.Println("User does not exist")
		w.Write([]byte("User does not exist"))
	}

	_, err = dbops.ChangeRole(&member)
	if err != nil {
		log.Println("changing role", err)
		w.Write([]byte("Error Occurred" + err.Error()))
	}

	w.Write([]byte("User Role Changed"))

}

func ViewEscrows(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Escrow Viewed" + r.URL.Path))
}

func CreatePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment link created" + r.URL.Path))
}

func ViewPayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment link viewed" + r.URL.Path))

}

func GenerateKeys(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("keys generated" + r.URL.Path))

}
func KybDet(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("kyb" + r.URL.Path))

}
