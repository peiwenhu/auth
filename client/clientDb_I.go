package client

type ClientDb_I interface {
	VerifyClient(c Client) error
}
