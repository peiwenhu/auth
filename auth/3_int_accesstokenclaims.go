package auth

import (
	"fmt"
	"time"
)

type accessTokenClaims struct {
	userid string
	priv   PVL
	exp    time.Time
}

const (
	field_exp    string = "exp"
	field_userid string = "sub"
	field_pvl    string = "pvl"
)

var accTokenFields = []string{
	field_exp,
	field_userid,
	field_pvl,
}

func (claims accessTokenClaims) toMap() map[string]interface{} {
	claimMap := make(map[string]interface{})
	claimMap[field_exp] = claims.exp.Format(time.RFC3339)
	claimMap[field_userid] = claims.userid
	claimMap[field_pvl] = int32(claims.priv)
	return claimMap
}

func newAccessTokenClaimsFromMap(claimMap map[string]interface{}) (*accessTokenClaims, error) {
	for _, field := range accTokenFields {
		if _, present := claimMap[field]; false == present {
			return nil, fmt.Errorf("Field not exist:%s", field)
		}
	}

	expTimeRepr, err := time.Parse(time.RFC3339, claimMap[field_exp].(string))
	if err != nil {
		return nil, fmt.Errorf("expiration time cannot be parsed:%v", err)
	}

	return &accessTokenClaims{
		userid: claimMap[field_userid].(string),
		priv:   PVL(claimMap[field_pvl].(int32)),
		exp:    expTimeRepr}, nil
}
