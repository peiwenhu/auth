package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocql/gocql"

	auth "github.com/peiwenhu/auth/auth"
	cassandra "github.com/peiwenhu/auth/cassandra"
	client "github.com/peiwenhu/auth/client"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {

	//-- get cli options
	log.Println("starting authsvc")
	configDir := flag.String("config_dir", "config", "main configuration file")

	flag.Parse()

	//-- read main config
	configData, err := ioutil.ReadFile(filepath.Join(*configDir, "main_config.json"))
	if err != nil {
		log.Println("failed to read main config file ", err)
		panic(err)
	}

	log.Printf("using configuration:\n%s\n", configData)

	var config mainConfig
	if err := config.fromJson(configData); err != nil {
		panic(err)
	}

	startService(config)

}

func getClients(clientsFilePath string) []client.Client {
	//-- read clients
	clientsData, err := ioutil.ReadFile(clientsFilePath)
	if err != nil {
		log.Fatalln("failed to read clients ", err)
		panic(err)
	}
	var clients struct {
		ClientList []client.Client `json:"clients"`
	}
	if err = json.Unmarshal(clientsData, &clients); err != nil {
		log.Fatalln("failed to unmarshall clients:", err)
		panic(err)
	}
	return clients.ClientList
}

func startService(config mainConfig) {
	log.Printf("using api version:%v\n", config.Version)
	//-- init client db acc
	clientdbacc := NewClientdbAcc(getClients(config.ClientsFilePath))

	dbHosts := config.DB_hosts

	if len(dbHosts) == 0 {
		log.Println("No database address specified in config." +
			"Use from env var CASSANDRA_SERVICE_HOST")

		envVal := os.Getenv("CASSANDRA_SERVICE_HOST")
		if len(envVal) == 0 {
			log.Println("No database address specified in env var." +
				"Use cassandra")
			dbHosts = []string{"cassandra"}
		} else {
			dbHosts = strings.Split(envVal, " ")
		}
	}

	log.Println("Using database host:", dbHosts)

	//-- set up db
	cluster := gocql.NewCluster(dbHosts...)
	cluster.Keyspace = config.DB_Keyspace
	session, err := cluster.CreateSession()
	if err != nil {
		panic(fmt.Errorf("failed to init cassandra:%v", err))
	}
	defer session.Close()

	userdbacc := cassandra.GetUserdbAccessor(session)

	//--- authenticator
	key, err := ioutil.ReadFile(config.KeyFilePath)
	if err != nil {
		panic(fmt.Errorf("failed to read key:%v", err))
	}

	authenticator := auth.NewAuthenticator(key)

	//-- build routes
	rp := NewRequestProcessor(authenticator, userdbacc, clientdbacc)

	routes := buildRoutes(config, rp)
	router := NewRouter(*routes)

	log.Fatal(http.ListenAndServeTLS(":"+config.Port, config.CertFilePath,
		config.KeyFilePath, router))
}
