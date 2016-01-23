FROM golang:1.5

ADD . /go/src/github.com/peiwenhu/auth/

ENV GO15VENDOREXPERIMENT 1

RUN ["go","install","github.com/peiwenhu/auth/authsvc"]

ADD ./config /authsvc/config/

ADD ./secrets /authsvc/secrets/

ENTRYPOINT ["/go/bin/authsvc","--config_dir","/authsvc/config/dev"]