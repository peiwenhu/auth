package auth

import (
	"testing"
)

func TestValidUser(t *testing.T) {
	useruuid := "abc123_"
	user, err := NewUserAuthInfo(useruuid, "token")
	if user.priv != None {
		t.Errorf("default priv should not be :%v ", user.priv)
	}

	if err != nil {
		t.Error("valid user considered invalid")
	}
	if user.UserId.Id != useruuid {
		t.Errorf("%v", user)
	}
	if user.accessToken != "token" {
		t.Errorf("%v", user)
	}
}

func TestInvalidUserRegex(t *testing.T) {
	useruuid := "abc123_!"
	_, err := NewUserAuthInfo(useruuid, "")
	if err == nil {
		t.Error("invalid user considered valid")
	}
}

func TestInvalidUserLen(t *testing.T) {
	useruuid := "a"
	_, err := NewUserAuthInfo(useruuid, "")
	if err == nil {
		t.Error("invalid user considered valid")
	}
}

func TestInvalidUserReserved(t *testing.T) {
	useruuid := "admin"
	_, err := NewUserAuthInfo(useruuid, "")
	if err == nil {
		t.Error("invalid user considered valid")
	}
}

func TestInvalidUserOtherLan(t *testing.T) {
	useruuid := "🐷"
	_, err := NewUserAuthInfo(useruuid, "")
	if err == nil {
		t.Error("invalid user considered valid")
	}
}
