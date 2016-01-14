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
	userId   UserId
	password []byte
}

func NewUserIDPassword(newUserIdStr string, password []byte) (*UserIDPassword, error) {
	newUserId, err := NewUserid(newUserIdStr)
	if err != nil {
		return nil, err
	}

	return &UserIDPassword{userId: *newUserId, password: password}, nil
}

func (u UserIDPassword) UserId() UserId {
	return u.userId
}

func (cred UserIDPassword) hashedPassword() []byte {
	hashedPassword, err := bcrypt.GenerateFromPassword(cred.password, bcrypt.DefaultCost)

	if err != nil {
		panic(fmt.Sprintf("Creating hashed password failed:%v", err))
	}

	return hashedPassword

}

func (cred UserIDPassword) verify(userStorage UserDb_I) error {
	fieldsToGet := []UserFieldName{UserField_Password}
	fieldsRes, err := userStorage.GetFields(cred.UserId(), fieldsToGet)
	if err != nil {
		return fmt.Errorf("failed to verify:%v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(fieldsRes[UserField_Password].(string)), cred.password) != nil {
		return ErrWrongUsernameOrPassword
	}
	return nil

}

type UserIDRefreshToken struct {
	userId       UserId
	clientId     string
	RefreshToken string
}

func (u UserIDRefreshToken) UserId() UserId {
	return u.userId
}

func (cred UserIDRefreshToken) verify(userStorage UserDb_I) error {
	refreshToken, err := userStorage.GetRefreshToken(cred.UserId(), cred.clientId)
	if err != nil {
		return fmt.Errorf("failed to verify:%v", err)
	}
	if refreshToken == nil || *refreshToken != cred.RefreshToken {
		return ErrWrongRefreshToken
	}
	return nil

}
