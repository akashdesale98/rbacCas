package main

import (
	"fmt"
	"log"
	"net/http"
	"rbacCas/controller"
	"rbacCas/dbops"
	"rbacCas/utils"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	sqlxadapter "github.com/memwey/casbin-sqlx-adapter"
)

var (
	r   *chi.Mux
	err error
)

func init() {
	err = dbops.ConnectDB()
	if err != nil {
		log.Fatal("Error in connectdb", err)
	}
}

func main() {
	r = chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	})

	r.Post("/signup", controller.Signup)
	r.Post("/signin", controller.Signin)

	text :=
		`
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act

	[role_definition]
	g = _, _

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = g(r.sub, p.sub) && r.obj == p.obj && regexMatch(r.act, p.act)`
	m, err := model.NewModelFromString(text)
	if err != nil {
		fmt.Println("err", err)
		panic(err)
	}

	opts := &sqlxadapter.AdapterOptions{
		DriverName:     "postgres",
		DataSourceName: "postgres://etcore:etcore@localhost/postgres?sslmode=disable",
		TableName:      "policy",
	}

	a := sqlxadapter.NewAdapterFromOptions(opts)
	// a := fileadapter.NewAdapter("./policy2.csv")

	e, err := casbin.NewEnforcer(m, a)
	// e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
	if err != nil {
		fmt.Println("err0", err)
		panic(err)
	}

	r.Route("/", func(r chi.Router) {
		r.Use(Authorizer(e))
		r.Post("/createPaymentsLinks", controller.CreatePayment)
		r.Post("/viewPaymentsLinks", controller.ViewPayment)
		r.Post("/addUser", controller.AddUser)
		r.Post("/changeRoles", controller.ChangeRoles)
		r.Post("/removeUser", controller.RemoveUser)
		r.Post("/viewEscrows", controller.ViewEscrows)
		r.Post("/generateKeys", controller.GenerateKeys)
		r.Post("/kyb", controller.GenerateKeys)
	})

	http.ListenAndServe(":3333", r)
}

func Authorizer(e *casbin.Enforcer) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			group, _, err := utils.ExtractTokenMetadata(r)
			method := r.Method
			path := r.URL.Path
			if err != nil {
				log.Println("err0", err)
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			// fmt.Println("group", group)
			// fmt.Println("path", path)
			// fmt.Println("method", method)
			ok, err := e.Enforce(group, path, method)
			if ok {
				next.ServeHTTP(w, r)
			} else {
				log.Println("err1", err)
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			}
		}
		return http.HandlerFunc(fn)
	}
}
