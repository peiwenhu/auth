package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Authenticator struct {
	key []byte
}

func NewAuthenticator(newKey []byte) (
	newObj *Authenticator) {
	return &Authenticator{key: newKey}
}

//-- No db access
func (authenticator Authenticator) VerifyPrivilege(
	userInfo UserAuthInfo, levelToMeet PVL) (ok bool, err error) {
	//if already cached in .priv then just use that
	if userInfo.priv != None {
		return userInfo.priv.isGoodFor(levelToMeet), nil
	}

	//-- get PVL

	accessClaims, err := authenticator.getAccessTokenClaims(userInfo.accessToken)
	if err != nil {
		return false, err
	}

	if accessClaims.userid != userInfo.UserId.Id {
		return false, fmt.Errorf("failed to verify privilege:User Id %s is not same as in claim %s",
			userInfo.UserId.Id, accessClaims.userid)
	}

	if time.Now().UTC().After(accessClaims.exp) {
		return false, fmt.Errorf("failed to verify privilege:access token expired")
	}

	userInfo.priv = accessClaims.priv
	return userInfo.priv.isGoodFor(levelToMeet), nil

}

func (authenticator Authenticator) refreshTokens(
	cred UserCredentials_I,
	userStorage UserDb_I) (*string, *string, error) {

	if err := cred.verify(userStorage); err != nil {
		return nil, nil, err
	}

	newRefreshToken, err := authenticator.createRefreshToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to refresh tokens:%v", err)
	}

	fieldsToGet := []UserFieldName{UserField_Priv}

	fields, err := userStorage.GetFields(cred.UserId(), fieldsToGet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to refresh tokens:%v", err)
	}

	priv := fields[UserField_Priv].(PVL)

	newAccessClaims := accessTokenClaims{
		userid: cred.UserId().Id,
		priv:   priv,
		exp:    time.Now().UTC().AddDate(0, 0, 1)}

	newAccessToken, err := authenticator.createAccessToken(newAccessClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to refresh tokens:%v", err)
	}

	fieldsToUpdate := make(map[UserFieldName]interface{})

	fieldsToUpdate[UserField_Refresh] = newRefreshToken

	if err = userStorage.UpdateUser(cred.UserId(), fieldsToUpdate); err != nil {
		return nil, nil, fmt.Errorf("failed to refresh tokens:%v", err)
	}

	return newAccessToken, newRefreshToken, nil

}

func (authenticator Authenticator) CreateUser(
	useridStr string, name string, password []byte,
	otherFields map[UserFieldName]interface{}, userStorage UserDb_I) (*string, *string, error) {

	userCred, err := NewUserIDPasswordWithEnc(useridStr, password)
	if err != nil {
		return nil, nil, ErrUserIdInvalid
	}
	//--  create tokens
	accessClaims := accessTokenClaims{
		userid: userCred.UserId().Id,
		priv:   RegularUser,
		exp:    time.Now().UTC().AddDate(0, 0, 1)}

	accessToken, err := authenticator.createAccessToken(accessClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("user creation failed:%v", err)
	}

	refreshToken, err := authenticator.createRefreshToken()
	if err != nil {
		return nil, nil, fmt.Errorf("user creation failed:%v", err)
	}

	//-- 3. insert user
	if err = userStorage.CreateUser(
		userCred.UserId(), name, userCred.hashedPassword,
		RegularUser, *refreshToken, otherFields); err != nil {
		return nil, nil, fmt.Errorf("user creation failed:%v", err)
	}

	return accessToken, refreshToken, nil
}

/* -------------------------------------
//---- Privates
--------------------------------------- */

const (
	refreshTokenLen = 32
)

func (a Authenticator) createAccessToken(claims accessTokenClaims) (*string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS256)

	//-- construct claims
	accessToken.Claims = claims.toMap()
	out, err := accessToken.SignedString([]byte(a.key))
	if err != nil {
		return nil, fmt.Errorf("Authenticator failed to generate accessToken: %v", err)
	}
	return &out, nil
}

func (a Authenticator) createRefreshToken() (*string, error) {

	refreshTokenBytes := make([]byte, refreshTokenLen)
	if _, err := io.ReadFull(rand.Reader, refreshTokenBytes); err != nil {
		return nil, fmt.Errorf("CreateUserAuth failed:%v", err)
	}

	encodedTokenStr := base64.URLEncoding.EncodeToString(refreshTokenBytes)
	return &encodedTokenStr, nil
}

func (authenticator Authenticator) getAccessTokenClaims(
	accessTokenStr string) (*accessTokenClaims, error) {

	accessToken, err := jwt.Parse(accessTokenStr,
		func(token *jwt.Token) (interface{}, error) {
			return authenticator.key, nil
		})

	if err != nil {
		return nil,
			fmt.Errorf("getAccessTokenClaims failed to verify accessToken:%v", err)
	} else if false == accessToken.Valid {
		return nil,
			fmt.Errorf("getAccessTokenClaims access token invalid")
	}

	accessClaims, err := newAccessTokenClaimsFromMap(accessToken.Claims)
	if err != nil {
		return nil, fmt.Errorf("getAccessTokenClaims failed to create claims map:%v", err)
	}

	return accessClaims, nil
}
