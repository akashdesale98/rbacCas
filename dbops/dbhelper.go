package dbops

import (
	"fmt"
	"log"
	"rbacCas/models"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var (
	db  *sqlx.DB
	err error
)

func init() {
	db, err = sqlx.Open("postgres", "postgres://etcore:etcore@localhost/postgres?sslmode=disable")
	if err != nil {
		log.Print("error while connecting db", err)
	}
}

func ConnectDB() error {
	if err = db.Ping(); err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}
	return err
}

func FetchUser(user_id string) ([]models.Members, error) {
	v := []models.Members{}

	query := `select * from members where username = ` + `'` + user_id + `'`
	err := db.Select(&v, query)
	if err != nil {
		log.Fatal("query error", err)
		return nil, err
	}

	fmt.Println("members", v)
	return v, nil
}

func CheckAdmin() int {
	var n int
	query := `SELECT count(*) FROM members`
	err := db.Get(&n, query)
	if err != nil {
		a := fmt.Sprintf("Scan() err = %v; want nil", err)
		fmt.Println("a::", a)
		return -1
	}
	return n
}

func CheckUser(user_id string) int {
	var n int
	query := `SELECT count(*) FROM members where username = ` + `'` + user_id + `'`
	err := db.Get(&n, query)
	if err != nil {
		a := fmt.Sprintf("Scan() err = %v; want nil", err)
		fmt.Println("a::", a)
		return -1
	}
	return n
}

func InsertUser(mem *models.Members) (int, error) {
	res, err := db.Exec(`
	INSERT INTO members(username, name, password,privilage) VALUES ($1, $2, $3,$4) RETURNING *;`,
		mem.Username,
		mem.Name,
		mem.Password,
		mem.Privilage)

	if err != nil {
		log.Println("error saving member: ", err)
		return 0, err
	}
	ra, _ := res.RowsAffected()
	return int(ra), nil
}

func DeleteUser(userid string) (int, error) {
	res, err := db.Exec(`DELETE * FROM members where username='$1';`, userid)
	if err != nil {
		log.Println("error saving member: ", err)
		return 0, err
	}
	ra, err := res.RowsAffected()
	if err != nil {
		log.Println("error saving member2: ", err)
		return 0, err
	}
	return int(ra), nil
}

func ChangeRole(mem *models.Members) (int, error) {
	res, err := db.Exec(`UPDATE members SET privilage = '$1' WHERE username = '$2';`, mem.Privilage, mem.Username)
	if err != nil {
		log.Println("error saving member: ", err)
		return 0, err
	}
	ra, err := res.RowsAffected()
	if err != nil {
		log.Println("error saving member2: ", err)
		return 0, err
	}
	return int(ra), nil
}
