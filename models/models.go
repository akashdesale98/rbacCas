package models

type Members struct {
	Username  string `db:"username" json:"username"`
	Password  string `db:"password" json:"password"`
	Name      string `db:"name" json:"name"`
	Id        int    `db:"id" json:"id"`
	Privilage string `db:"privilage" json:"privilage"`
	Token     string `db:"token" json:"token"`
}

type User struct {
	Username  string `db:"username" json:"username"`
	Password  string `db:"password" json:"password"`
	Name      string `db:"name" json:"name"`
	Privilage string `db:"privilage" json:"privilage"`
	Id        int    `db:"id" json:"id"`
}
