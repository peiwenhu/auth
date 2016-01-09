package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/peiwenhu/auth/client"
)

func TestCreateAccessToken(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	sampleTime, err := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{uuid: "testuuid", priv: God, exp: sampleTime}
	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	accToken, err := authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}
	if accToken != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ."+
		"pZER8fTP_nUdcZSUbYpBNFXlLuiKbb4DLke_ItSUWsY" {
		t.Errorf("access token is not as expected:%v", accToken)
	}
}

func TestCreateRefreshToken(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	refresh, err := authenForTest.createRefreshToken()
	if err != nil {
		t.Errorf("createRefreshToken failed:%v", err)
	}
	if len(refresh) == 0 {
		t.Errorf("refresh token is empty")
	}
}

func TestGetAccessTokenClaims(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	sampleTime, err := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{uuid: "testuuid", priv: God, exp: sampleTime}
	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ." +
		"pZER8fTP_nUdcZSUbYpBNFXlLuiKbb4DLke_ItSUWsY"

	userInfo, err := NewUserAuthInfo("testuuid", accToken)
	if err != nil {
		t.Error(err)
	}

	accClaimsToTest, err := authenForTest.getAccessTokenClaims(*userInfo)
	if err != nil {
		t.Error(err)
	}

	if *accClaimsToTest != accessClaims {
		t.Errorf("accessClaim not expected:%v", *accClaimsToTest)
	}
}

func TestGetAccessTokenClaimsInvalidSig(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)
	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ." +
		"badsig"

	userInfo, err := NewUserAuthInfo("testuuid", accToken)
	if err != nil {
		t.Error(err)
	}

	_, err = authenForTest.getAccessTokenClaims(*userInfo)
	if err == nil {
		t.Error("sig err should have been there")
	}

}

func TestGetAccessTokenClaimsInvalidClaim(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)
	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIyMDE1LTEzLTE1VDE0OjAwOjEzWiIsInB2bCI6OTk5OTk5OTk5OSwic3ViIjoidGVzdHV1aWQifQ.lWaVuMN2fif7ajEa-vnGJ293ZQm-KbZH1GDfSd8x6RU"

	userInfo, err := NewUserAuthInfo("testuuid", accToken)
	if err != nil {
		t.Error(err)
	}

	_, err = authenForTest.getAccessTokenClaims(*userInfo)
	if err == nil {
		t.Error("claim err should have been there")
	}

}

func TestGetAccessTokenClaimsInvalidUUID(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)
	//client
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	accToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOiIyMDE1LTA5LTE1VDE0OjAwOjEzWiIsInB2bCI6MSwic3ViIjoidGVzdHV1aWQifQ." +
		"pZER8fTP_nUdcZSUbYpBNFXlLuiKbb4DLke_ItSUWsY"

	userInfo, err := NewUserAuthInfo("anotheruuid", accToken)
	if err != nil {
		t.Error(err)
	}

	_, err = authenForTest.getAccessTokenClaims(*userInfo)
	if err == nil {
		t.Error("uuid err should have been there")
	}

}

func TestVerifyPrivilege(t *testing.T) {
	testKey := []byte(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNemV41`)

	//client
	clientInfo := client.Client{Id: "a", Secret: "b"}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockClient := client.NewMockClientDb_I(ctrl)
	authenForTest := NewAuthenticator(testKey, mockClient)

	//-- access token
	sampleTime, err := time.Parse(time.RFC3339, "2016-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{uuid: "testuuid", priv: RegularUser, exp: sampleTime}

	accToken, err := authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}

	//-- user info

	userInfo, err := NewUserAuthInfo("testuuid", accToken)
	if err != nil {
		t.Error(err)
	}

	mockClient.EXPECT().VerifyClient(clientInfo).Return(nil)

	if ok, err := authenForTest.VerifyPrivilege(*userInfo, clientInfo, God); err != nil {
		t.Error(err)
	} else if ok != false {
		t.Error("Regular should < God")
	}

	userInfo.priv = None
	mockClient.EXPECT().VerifyClient(clientInfo).Return(errors.New("error!"))
	if _, err := authenForTest.VerifyPrivilege(*userInfo, clientInfo, RegularUser); err == nil {
		t.Error("verify client should get error")
	}

	sampleTime, err = time.Parse(time.RFC3339, "1990-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims = accessTokenClaims{uuid: "testuuid", priv: RegularUser, exp: sampleTime}

	accToken, err = authenForTest.createAccessToken(accessClaims)
	if err != nil {
		t.Errorf("createAccessToken failed:%v", err)
	}

	userInfo, err = NewUserAuthInfo("testuuid", accToken)
	mockClient.EXPECT().VerifyClient(clientInfo).Return(nil)
	if _, err := authenForTest.VerifyPrivilege(*userInfo, clientInfo, RegularUser); err == nil {
		t.Error("verify client should get time error")
	}
}
