package auth

type UserAuthInfo struct {
	UserId      UserId
	accessToken string
	priv        PVL
}

func NewUserAuthInfo(newUserIdStr string, newAccessToken string) (
	*UserAuthInfo, error) {
	newUserId, err := NewUserid(newUserIdStr)
	if err != nil {
		return nil, err
	}
	newUser := &UserAuthInfo{UserId: *newUserId, accessToken: newAccessToken, priv: None}
	return newUser, nil
}
