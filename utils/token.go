package utils

import (
	"errors"
	"fmt"
	"net/http"
	"rbacCas/dbops"
	"rbacCas/models"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const ACCESS_SECRET = "jdnfksdmfksd"

func CreateToken(user models.Members) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = user.Username
	atClaims["group"] = user.Privilage
	a := time.Now().Add(time.Minute * 15).Unix()
	fmt.Println("a ", a)
	atClaims["exp"] = strconv.FormatInt(a, 10)
	fmt.Println("str a", atClaims["exp"])
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(ACCESS_SECRET))
	if err != nil {
		return "", err
	}
	return token, nil
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	fmt.Println("toke", bearToken)
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	fmt.Println("extratc", tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ACCESS_SECRET), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func ExtractTokenMetadata(r *http.Request) (string, bool, error) {
	token, err := VerifyToken(r)
	if err != nil {
		fmt.Println("1")
		return "", false, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		username, ok := claims["user_id"].(string)
		if !ok {
			fmt.Println("1")
			return "", false, errors.New("username type cast")
		}
		n := dbops.CheckUser(username)
		if n < 1 {
			fmt.Println("1")
			return "", false, errors.New("user does not exist")
		}
		group, ok := claims["group"].(string)
		if !ok {
			fmt.Println("1")
			return "", false, errors.New("group type cast")
		}
		exp, ok := claims["exp"].(string)
		if !ok {
			fmt.Println("1")
			return "", false, errors.New("exp type cast")
		}

		i, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			fmt.Println("1")
			return "", false, errors.New("error converting timestamp")
		}
		tm := time.Unix(i, 0)
		if tm.Before(time.Now()) {
			fmt.Println("1")
			return "", false, errors.New("token is expired")
		}

		return group, true, err
	}
	return "", false, errors.New("invalid token")
}
