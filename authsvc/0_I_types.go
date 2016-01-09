package main

import (
	"encoding/json"
	"errors"
)

type mainConfig struct {
	Version         string   `json:"version"`
	Port            string   `json:"port"`
	DB_Keyspace     string   `json:"db_keyspace"`
	DB_hosts        []string `json:"db_hosts"`
	CertFilePath    string   `json:"cert_file_path"`
	KeyFilePath     string   `json:"key_file_path"`
	ClientsFilePath string   `json:"clients_file_path"`
}

func (c *mainConfig) fromJson(data []byte) error {
	return json.Unmarshal(data, c)
}

type apiError struct {
	code int
	err  error
}

var ErrInternal = errors.New("Sorry, something may have gone wrong. Please give me some time to fix")
