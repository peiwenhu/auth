package auth

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestCreateAccessToken(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	sampleTime, err := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{userid: "testuuid", priv: God, exp: sampleTime}

	authenForTest := NewAuthenticator(testKey)

	accToken, err := authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}
	if *accToken != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ."+
		"pZER8fTP_nUdcZSUbYpBNFXlLuiKbb4DLke_ItSUWsY" {
		t.Errorf("access token is not as expected:%v", accToken)
	}
}

func TestCreateRefreshToken(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	authenForTest := NewAuthenticator(testKey)

	refresh, err := authenForTest.createRefreshToken()
	if err != nil {
		t.Errorf("createRefreshToken failed:%v", err)
		return
	}
	if len(*refresh) == 0 {
		t.Errorf("refresh token is empty")
	}
}

func TestGetAccessTokenClaims(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	sampleTime, err := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{userid: "testuuid", priv: God, exp: sampleTime}
	//client
	authenForTest := NewAuthenticator(testKey)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ." +
		"pZER8fTP_nUdcZSUbYpBNFXlLuiKbb4DLke_ItSUWsY"

	accClaimsToTest, err := authenForTest.decodeAccessToken(accToken)
	if err != nil {
		t.Error(err)
	}

	if *accClaimsToTest != accessClaims {
		t.Errorf("accessClaim not expected:%v", *accClaimsToTest)
	}
}

func TestGetAccessTokenClaimsInvalidSig(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)
	authenForTest := NewAuthenticator(testKey)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ." +
		"badsig"

	_, err := authenForTest.decodeAccessToken(accToken)
	if err == nil {
		t.Error("sig err should have been there")
	}

}

func TestGetAccessTokenClaimsInvalidClaim(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)
	authenForTest := NewAuthenticator(testKey)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIyMDE1LTEzLTE1VDE0OjAwOjEzWiIsInB2bCI6OTk5OTk5OTk5OSwic3ViIjoidGVzdHV1aWQifQ.lWaVuMN2fif7ajEa-vnGJ293ZQm-KbZH1GDfSd8x6RU"

	_, err := authenForTest.decodeAccessToken(accToken)
	if err == nil {
		t.Error("claim err should have been there")
	}

}

func TestVerifyPrivilege(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	authenForTest := NewAuthenticator(testKey)

	//-- access token
	sampleTime, err := time.Parse(time.RFC3339, "2016-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{userid: "testuuid", priv: RegularUser, exp: sampleTime}

	accToken, err := authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}

	//-- user info

	userInfo, err := NewUserAuthInfo("testuuid", *accToken)
	if err != nil {
		t.Error(err)
	}

	if ok, err := authenForTest.VerifyPrivilege(*userInfo, God); err != nil {
		t.Error(err)
	} else if ok != false {
		t.Error("Regular should < God")
	}

	sampleTime, err = time.Parse(time.RFC3339, "1990-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims = accessTokenClaims{userid: "testuuid", priv: RegularUser, exp: sampleTime}

	accToken, err = authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}

	userInfo, err = NewUserAuthInfo("testuuid", *accToken)

	if _, err := authenForTest.VerifyPrivilege(*userInfo, RegularUser); err == nil {
		t.Error("verify client should get time error")
	}
}

func TestCreateUser(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	authenForTest := NewAuthenticator(testKey)

	//-- params
	userid := "salmon"
	username := "the fish"
	password := "password"
	cred, _ := NewUserIDPassword(userid, []byte(password))
	clientId := "ios"
	otherFields := make(map[UserFieldName]interface{})
	otherFields[UserField_Language] = "en"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockUserDb := NewMockUserDb_I(ctrl)

	mockUserDb.EXPECT().CreateUser(cred.UserId(), username, gomock.Any(), RegularUser, otherFields)
	mockUserDb.EXPECT().SetRefreshToken(cred.UserId(), clientId, gomock.Any())
	_, _, err := authenForTest.CreateUser(
		userid, username, []byte(password), clientId, otherFields, mockUserDb)
	if err != nil {
		t.Error("create user failed:%v", err)
	}
}
