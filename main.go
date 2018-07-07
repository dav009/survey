package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/github"
	"github.com/dghubble/sessions"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

type Config struct {
	SessionSecret      string
	JwtSecret          string
	GithubClientID     string
	GithubClientSecret string
	GoogleFormUrl      string
	CallbackUrl        string
	Address            string
}

var config = Config{
	SessionSecret:      os.Getenv("SESSION_SECRET"),
	JwtSecret:          os.Getenv("JWT_SECRET"),
	GithubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
	GithubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	Address:            os.Getenv("ADDRESS"),
	CallbackUrl:        os.Getenv("CALLBACK_URL"),
	GoogleFormUrl:      os.Getenv("GOOGLE_FORM_URL"),
}

const (
	sessionName     = "colombiadev-survey"
	sessionUserKey  = "githubID"
	sessionUserName = "githubUsername"
)

var sessionStore = sessions.NewCookieStore([]byte(config.SessionSecret), nil)

func New() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", welcomeHandler())
	mux.Handle("/github", requireLogin(http.HandlerFunc(githubSurveyHandler)))
	mux.Handle("/anonymous", http.HandlerFunc(anonymousSurveyHandler))
	mux.HandleFunc("/logout", logoutHandler)
	oauth2Config := &oauth2.Config{
		ClientID:     config.GithubClientID,
		ClientSecret: config.GithubClientSecret,
		RedirectURL:  config.CallbackUrl,
		Endpoint:     githubOAuth2.Endpoint,
	}
	stateConfig := gologin.DebugOnlyCookieConfig
	mux.Handle("/login", github.StateHandler(stateConfig, github.LoginHandler(oauth2Config, nil)))
	mux.Handle("/OauthCallback", github.StateHandler(stateConfig, github.CallbackHandler(oauth2Config, issueSession(), nil)))
	return mux
}

func issueSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session := sessionStore.New(sessionName)
		session.Values[sessionUserKey] = *githubUser.ID
		session.Values[sessionUserName] = *githubUser.Login

		session.Save(w)

		http.Redirect(w, req, "/github", http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

type PageData struct {
	Logged   bool
	Username string
}

func welcomeHandler() func(http.ResponseWriter, *http.Request) {

	tmpl, err := template.ParseFiles("home.html")
	if err != nil {
		panic("error while rendering  home page template")
	}
	f := func(w http.ResponseWriter, req *http.Request) {

		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		data := PageData{
			Logged:   isAuthenticated(req),
			Username: "",
		}

		if data.Logged {
			s, err := sessionStore.Get(req, sessionName)
			if err != nil {
				http.Error(w, "could not get user session", http.StatusInternalServerError)
			}
			data.Username = s.Values[sessionUserName].(string)
		}
		tmpl.Execute(w, data)
	}
	return f
}

func anonymousSurveyHandler(w http.ResponseWriter, req *http.Request) {
	formJWT := "anonymous"
	link := fmt.Sprintf(config.GoogleFormUrl, formJWT)
	http.Redirect(w, req, link, http.StatusSeeOther)
}

func githubSurveyHandler(w http.ResponseWriter, req *http.Request) {
	s, err := sessionStore.Get(req, sessionName)
	if err != nil {
		http.Error(w, "could not get user session", http.StatusInternalServerError)
	}
	formJWT := generateJWT(hashUser(s.Values[sessionUserName].(string)))
	link := fmt.Sprintf(config.GoogleFormUrl, formJWT)
	http.Redirect(w, req, link, http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		sessionStore.Destroy(w, sessionName)
	}
	http.Redirect(w, req, "/", http.StatusFound)
}

func requireLogin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if !isAuthenticated(req) {
			http.Redirect(w, req, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

func isAuthenticated(req *http.Request) bool {
	if _, err := sessionStore.Get(req, sessionName); err == nil {
		return true
	}
	return false
}

func main() {

	log.Printf("Starting Server listening on %s\n", config.Address)
	err := http.ListenAndServe(config.Address, New())
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func generateJWT(hashedUsername string) string {
	t := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = 0
	claims["hashedUsername"] = hashedUsername
	claims["at"] = time.Now().Unix()
	t.Claims = claims
	tokenString, err := t.SignedString([]byte(config.JwtSecret))
	if err != nil {
		fmt.Println(err)
	}
	return tokenString
}

func hashUser(username string) string {
	// add some real user hashing here
	return fmt.Sprintf("hashed_username_%s", username)

}
