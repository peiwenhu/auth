package auth

type UserFieldName string

const (
	UserField_Priv     UserFieldName = "priv"
	UserField_Refresh  UserFieldName = "refresh_token"
	UserField_UserId   UserFieldName = "userid"
	UserField_Name     UserFieldName = "username"
	UserField_Password UserFieldName = "password"
	UserField_Language UserFieldName = "lang"
)
