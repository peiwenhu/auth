package auth

import (
	"testing"
	"time"
)

func TestToMap(t *testing.T) {
	sampleTime, err := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if err != nil {
		t.Errorf("sample time generated error:%v", err)
	}
	accessClaims := accessTokenClaims{uuid: "testuuid", priv: God, exp: sampleTime}
	mapRepr := accessClaims.toMap()
	if mapRepr[field_exp] != "2015-09-15T14:00:13Z" {
		t.Errorf("time conversion wrong:%v", mapRepr)
	}
	if mapRepr[field_uuid] != "testuuid" {
		t.Errorf("uuid conversion wrong:%v", mapRepr)
	}
	if PVL(mapRepr[field_pvl].(int32)) != God {
		t.Errorf("pvl conversion wrong:%v", mapRepr)
	}

}

func TestFromMap(t *testing.T) {
	mapRepr := make(map[string]interface{})
	mapRepr[field_exp] = "2015-09-15T14:00:13Z"
	mapRepr[field_pvl] = int32(God)
	mapRepr[field_uuid] = "testuuid"

	accessClaims, err := newAccessTokenClaimsFromMap(mapRepr)

	if err != nil {
		t.Errorf("testing conversion from map failed:%v", err)
	}

	sampleTime, _ := time.Parse(time.RFC3339, "2015-09-15T14:00:13Z")
	if accessClaims.exp != sampleTime {
		t.Errorf("time conversion wrong:%v", accessClaims)
	}
	if accessClaims.userid != "testuserid" {
		t.Errorf("uuid conversion wrong:%v", accessClaims)
	}
	if accessClaims.priv != God {
		t.Errorf("priv conversion wrong:%v", accessClaims)
	}
}

func TestFromMapMissingField(t *testing.T) {
	mapRepr := make(map[string]interface{})
	mapRepr[field_exp] = "2015-09-15T14:00:13Z"
	mapRepr[field_pvl] = int32(God)

	_, err := newAccessTokenClaimsFromMap(mapRepr)

	if err == nil {
		t.Errorf("failed to find a field missing")
	}

}
func TestFromMapInvalidTimeField(t *testing.T) {
	mapRepr := make(map[string]interface{})
	mapRepr[field_exp] = "2015-13-15T14:00:13Z"
	mapRepr[field_pvl] = int32(God)
	mapRepr[field_uuid] = "testuuid"

	_, err := newAccessTokenClaimsFromMap(mapRepr)

	if err == nil {
		t.Errorf("failed to find a field missing")
	}

}
