package auth

type UserFieldName string

const (
	UserField_Priv     UserFieldName = "priv"
	UserField_UserId   UserFieldName = "userid"
	UserField_Name     UserFieldName = "username"
	UserField_Password UserFieldName = "password"
	UserField_Language UserFieldName = "lang"
)

type RefreshFieldName string

const (
	RefreshField_UserId     RefreshFieldName = "userid"
	RefreshField_ClientId   RefreshFieldName = "client_id"
	RefreshField_RefreshTok RefreshFieldName = "refresh_token"
)
