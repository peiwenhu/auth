package auth

type UserDb_I interface {
	GetFields(userid UserId, fields []UserFieldName) (map[UserFieldName]interface{}, error)

	UpdateUser(userid UserId, fields map[UserFieldName]interface{}) error

	CreateUser(userid UserId, name string, hashedPassword []byte, priv PVL, otherFields map[UserFieldName]interface{}) error

	GetRefreshToken(userid UserId, clientId string) (*string, error)

	SetRefreshToken(userid UserId, clientId string, refreshToken string) error
}
