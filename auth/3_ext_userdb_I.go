package auth

type UserDb_I interface {
	GetFields(userid UserId, fields []UserFieldName) (map[UserFieldName]interface{}, error)

	UpdateUser(userid UserId, fields map[UserFieldName]interface{}) error

	CreateUser(userid UserId, name string, hashedPassword []byte, priv PVL,
		refreshToken string, otherFields map[UserFieldName]interface{}) error
}
