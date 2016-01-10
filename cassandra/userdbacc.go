package cassandra

import (
	"fmt"

	"github.com/gocql/gocql"
	auth "github.com/peiwenhu/auth/auth"
)

type userdbAcc struct {
	session *gocql.Session
}

func GetUserdbAccessor(s *gocql.Session) auth.UserDb_I {
	userdb := &userdbAcc{session: s}
	return userdb
}

func (userdb userdbAcc) GetFields(
	userid auth.UserId, fields []auth.UserFieldName) (
	map[auth.UserFieldName]interface{}, error) {
	rawQueryStr := "SELECT "
	for _, str := range fields {
		rawQueryStr = fmt.Sprintf("%s %s", rawQueryStr, str)
	}
	rawQueryStr = fmt.Sprintf(
		"%s FROM users WHERE %s = ? LIMIT 1", rawQueryStr, auth.UserField_UserId)

	query := userdb.session.Query(rawQueryStr, userid)
	cqlRes := make(map[string]interface{})
	if err := query.MapScan(cqlRes); err != nil {
		if err == gocql.ErrNotFound {
			return nil, auth.ErrNotFound
		}
		return nil, fmt.Errorf("Get user fields failed:%v", err)
	}
	ourRes := make(map[auth.UserFieldName]interface{})
	for _, key := range fields {
		val := cqlRes[string(key)]
		ourRes[key] = val
	}
	return ourRes, nil

}
func (userdb userdbAcc) UpdateUser(
	userid auth.UserId, fields map[auth.UserFieldName]interface{}) error {
	return nil
}
func (userdb userdbAcc) CreateUser(
	userid auth.UserId, name string,
	hashedPassword []byte, priv auth.PVL,
	refreshToken string, otherFields map[auth.UserFieldName]interface{}) error {

	rawQueryStr := fmt.Sprintf("INSERT INTO users (%s,%s,%s,%s,%s,%s) "+
		" VALUES(?,?,?,?,?,?) IF NOT EXISTS",
		auth.UserField_UserId, auth.UserField_Name, auth.UserField_Password,
		auth.UserField_Priv, auth.UserField_Refresh, auth.UserField_Language)

	query := userdb.session.Query(rawQueryStr,
		userid.Id, name, hashedPassword, priv, refreshToken, otherFields[auth.UserField_Language])

	dummyRes := make(map[string]interface{})
	applied, err := query.MapScanCAS(dummyRes)
	if err != nil {
		return fmt.Errorf("create user failed:%v", err)
	}
	if applied == false {
		return auth.ErrUserExists
	}
	return nil
}
