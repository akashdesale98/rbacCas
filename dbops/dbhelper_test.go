package dbops

import (
	"testing"
)

func TestFetchUser(t *testing.T) {
	a := CheckUser("akash")
	if a == 0 {
		t.Fatal("no user found")
	}
	if a == -1 {
		t.Fatal("something went wrong")
	}
}
