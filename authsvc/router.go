package main

import (
	"github.com/gorilla/mux"
	"net/http"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter(routes Routes) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return router
}

func buildRoutes(config mainConfig, rp *RequestProcessor) *Routes {
	var version string = config.Version

	var routes = Routes{
		Route{
			"Register",
			"POST",
			"/api/v" + version + "/createuser",
			rp.createUserHandler,
		},
		Route{
			"Login",
			"POST",
			"/api/v" + version + "/login",
			rp.loginHandler,
		},
	}

	return &routes
}
