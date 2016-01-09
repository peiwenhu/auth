#!/bin/sh

mockgen -source auth/*userdb_I.go -destination auth/mock_userdb.go -package auth
mockgen -source auth/*usercredentials_I.go -destination auth/mock_usercredentials.go -package auth