package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/astaxie/beego/session"
	oidc "github.com/coreos/go-oidc"
	gcontext "github.com/gorilla/context"
	flags "github.com/jessevdk/go-flags"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

type Options struct {
	ClientID     string `long:"client-id" description:"Azure AD application ID"`
	ClientSecret string `long:"client-secret" description:"Azure AD application secret key"`
	Issuer       string `long:"issuer" description:"Azure AD OAuth 2.0 issuer URL" default:"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"`
	Port         int    `long:"port" description:"The port which the HTTP server will bind to." default:"3000"`
}

type Server struct {
	context     context.Context
	provider    *oidc.Provider
	oauthConfig *oauth2.Config
	opts        *Options
	sessionName string
}

type Claim struct {
	Key   string
	Value string
}

var globalSessions *session.Manager

func NewServer(opts *Options) (*Server, error) {
	ctx := oidc.ClientContext(context.Background(), &http.Client{})
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}

	oauthConfig := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("http://localhost:%d/oidc/callback", opts.Port),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	server := &Server{
		provider:    provider,
		oauthConfig: oauthConfig,
		opts:        opts,
		context:     ctx,
		sessionName: "oidc-sample",
	}

	return server, nil
}

func (s *Server) login(w http.ResponseWriter, req *http.Request) {
	sess, err := globalSessions.SessionStart(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.SessionRelease(w)

	uuidVar, err := uuid.NewV4()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	state := uuidVar.String()
	sess.Set("state", state)

	redirectURL := s.oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("response_mode", "form_post"),
	)
	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
}

func (s *Server) callback(w http.ResponseWriter, req *http.Request) {
	sess, err := globalSessions.SessionStart(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.SessionRelease(w)

	state := sess.Get("state")
	if state == nil {
		http.Error(w, "state was not found in session.", http.StatusForbidden)
		return
	}

	if err = req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	errCode := req.FormValue("error")
	if errCode != "" {
		errDescription := req.FormValue("error_description")
		http.Error(w, fmt.Sprintf("Failed to auth - %s: %s", errCode, errDescription), http.StatusForbidden)
		return
	}

	if state.(string) != req.FormValue("state") {
		http.Error(w, "Invalid state", http.StatusForbidden)
		return
	}

	code := req.FormValue("code")

	accessResp, err := s.oauthConfig.Exchange(s.context, code)
	if err != nil {
		http.Error(w, "Fail to exchange access code", http.StatusInternalServerError)
		return
	}

	verifier := s.provider.Verifier(&oidc.Config{
		ClientID: s.opts.ClientID,
	})
	idToken, err := verifier.Verify(s.context, accessResp.Extra("id_token").(string))
	if err != nil {
		http.Error(w, "Invalid ID token", http.StatusInternalServerError)
		return
	}

	var idTokenClaims *json.RawMessage
	if err = idToken.Claims(&idTokenClaims); err != nil {
		http.Error(w, "Invalid ID token claims", http.StatusInternalServerError)
		return
	}

	claimsBytes, err := idTokenClaims.MarshalJSON()
	if err != nil {
		http.Error(w, "Cannot marshal ID token claims", http.StatusInternalServerError)
		return
	}

	sess.Set("id", accessResp.Extra("id_token").(string))
	sess.Set("access", accessResp.AccessToken)
	sess.Set("claims", string(claimsBytes))

	http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
}

func (s *Server) logout(w http.ResponseWriter, req *http.Request) {
	sess, err := globalSessions.SessionStart(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.SessionRelease(w)

	if err = sess.Flush(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
}

func (s *Server) index(w http.ResponseWriter, req *http.Request) {
	sess, err := globalSessions.SessionStart(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sess.SessionRelease(w)

	data := struct {
		LoggedIn bool
		Claims   []Claim
	}{}

	claimsInSession := sess.Get("claims")
	if claimsInSession != nil {
		var claims map[string]interface{}
		if err = json.Unmarshal([]byte(claimsInSession.(string)), &claims); err != nil {
			http.Error(w, "Invalid id token claims", http.StatusInternalServerError)
			return
		}

		data.LoggedIn = true
		for name, value := range claims {
			data.Claims = append(data.Claims, Claim{name, fmt.Sprintf("%v", value)})
		}
	}

	access := sess.Get("access")
	if access != nil {
		data.Claims = append(data.Claims, Claim{"access_token", fmt.Sprintf("%v", access)})
	}

	tpl := `<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Azure AD OAuth 2.0 OpenID Connect Sample</title>
	</head>
	<body>
		<div>
			{{if .LoggedIn}}
				<a href="/oidc/logout">Logout</a>
			{{else}}
				<a href="/oidc/login">Login</a>
			{{end}}
		</div>
		<div>
			{{range .Claims}}
				<div>
					{{.Key}} = {{.Value}}
				</div>
			{{end}}
		</div>
	</body>
</html>
`
	t, err := template.New("index").Parse(tpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/login", s.login)
	mux.HandleFunc("/oidc/callback", s.callback)
	mux.HandleFunc("/oidc/logout", s.logout)
	mux.HandleFunc("/", s.index)
	portStr := fmt.Sprintf(":%d", s.opts.Port)
	log.Printf("Listen on http://0.0.0.0%s\n", portStr)
	return http.ListenAndServe(portStr, gcontext.ClearHandler(mux))
}

func main() {
	var opts Options
	_, err := flags.Parse(&opts)
	if err != nil {
		if flags.WroteHelp(err) {
			return
		}
		log.Fatal(err)
	}

	globalSessions, err = session.NewManager("memory", &session.ManagerConfig{
		CookieName:      "oauth2-oidc-sample",
		EnableSetCookie: true,
		Gclifetime:      3600,
		Maxlifetime:     3600,
		Secure:          false,
	})
	if err != nil {
		log.Fatal(err)
	}
	go globalSessions.GC()

	server, err := NewServer(&opts)
	if err != nil {
		log.Fatal(err)
	}

	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
