package main

import (
	client "github.com/peiwenhu/auth/client"
)

type clientdbAcc struct {
	clientSecretMap map[string]string
}

func NewClientdbAcc(clients []client.Client) *clientdbAcc {
	clientdb := new(clientdbAcc)
	clientdb.clientSecretMap = make(map[string]string, len(clients))
	for _, c := range clients {
		clientdb.clientSecretMap[c.Id] = c.Secret
	}
	return clientdb
}

func (clientdb clientdbAcc) VerifyClient(c client.Client) error {
	secret := clientdb.clientSecretMap[c.Id]
	if secret != c.Secret {
		return client.ErrBadClient
	}
	return nil
}
