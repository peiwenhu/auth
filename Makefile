.PHONY: vendor \
	test \
	testcov \
	dbrun \
	dkbuilddev \
	dkrun \
	

GOPATH:=${PWD}/../../../..
GO15VENDOREXPERIMENT=1
export GOPATH
export GO15VENDOREXPERIMENT

NOVENDOR:=$(shell glide novendor)

vendor: 
	glide up

fmt:
	go fmt ./...

test:			
	go test ${NOVENDOR}

testcov:
	go test ./$(DIR)/... -coverprofile=coverage.out -covermode=count
	go tool cover -html=coverage.out

#---- db
dbrun:
	docker run --name auth_cass -p 9042:9042 -d cassandra:2.2 

#---- app
dkbuilddev:
	docker build -t authsvc -f Dockerfile_dev .
dkrun:
	docker run --link auth_cass:cassandra --rm -it -p 10443:443 authsvc