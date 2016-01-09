package auth

type PVL int32

const (
	None PVL = iota //0
	God
	Admin
	PremiumUser
	RegularUser
)

func (priv PVL) isValid() bool {
	return priv == None || priv == RegularUser || priv == PremiumUser || priv == Admin || priv == God
}

func (priv PVL) isGoodFor(level PVL) bool {
	if priv == None {
		return false
	}
	return priv <= level
}
