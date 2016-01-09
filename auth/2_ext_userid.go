package auth

import (
	validator "gopkg.in/validator.v2"
)

type UserId struct {
	Id string `validate:"min=5,max=32,regexp=^[a-zA-Z_0-9]*$,user_notstopword"`
}

func NewUserid(newId string) (*UserId, error) {
	newUser := &UserId{Id: newId}
	if err := newUser.isValid(); err != nil {
		return nil, err
	}
	return newUser, nil
}

/* -------------------------------------
//---- Privates
--------------------------------------- */

func init() {
	validator.SetValidationFunc("user_notstopword", notReservedWord)
}

func (u UserId) isValid() error {
	return validator.Validate(u)
}
