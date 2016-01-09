package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type UserCredentials_I interface {
	UserId() UserId
	verify(userStorage UserDb_I) error
}

type UserIDPassword struct {
	userId         UserId
	hashedPassword []byte
}

func NewUserIDPasswordWithEnc(newUserIdStr string, password []byte) (*UserIDPassword, error) {
	newUserId, err := NewUserid(newUserIdStr)
	if err != nil {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &UserIDPassword{userId: *newUserId, hashedPassword: hashedPassword}, nil
}

func (u UserIDPassword) UserId() UserId {
	return u.userId
}

func (cred UserIDPassword) verify(userStorage UserDb_I) error {
	fieldsToGet := []UserFieldName{UserField_Password}
	fieldsRes, err := userStorage.GetFields(cred.UserId(), fieldsToGet)
	if err != nil {
		return fmt.Errorf("failed to verify:%v", err)
	}
	if fieldsRes[UserField_Password] != string(cred.hashedPassword) {
		return ErrWrongUsernameOrPassword
	}
	return nil

}

type UserIDRefreshToken struct {
	userId       UserId
	RefreshToken string
}

func (u UserIDRefreshToken) UserId() UserId {
	return u.userId
}

func (cred UserIDRefreshToken) verify(userStorage UserDb_I) error {
	fieldsToGet := []UserFieldName{UserField_Refresh}
	fieldsRes, err := userStorage.GetFields(cred.UserId(), fieldsToGet)
	if err != nil {
		return fmt.Errorf("failed to verify:%v", err)
	}
	if fieldsRes[UserField_Refresh] != cred.RefreshToken {
		return ErrWrongRefreshToken
	}
	return nil

}
