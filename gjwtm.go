package jwt_mdl

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"regexp"
	"strings"
)

type TokenExtractor func(r *http.Request) (string, error)
type StoreToken func(
	w http.ResponseWriter,
	r *http.Request,
	token *jwt.Token) error

type Options struct {
	// see: https://github.com/dgrijalva/jwt-go/blob/master/token.go
	// mandatory.
	// used to supply the private key for token hash validation
	KeyFunc jwt.Keyfunc

	// used to validate the jwt
	// default value is jwt.SigningMethodHS256
	SigningMethod jwt.SigningMethod

	// Function to extract the token from request.
	// The default implementation use the specification defined in:
	// https://jwt.io/introduction/
	Extractor TokenExtractor

	// store the token
	// this method is mandatory. use this to store the JWT object and/or
	// validate the JWT token value
	Store StoreToken
}

type JwtMiddleware struct {
	options Options
}

func New(options Options) *JwtMiddleware {
	if options.Store == nil {
		panic("Store is mandatory")
	}

	if options.KeyFunc == nil {
		panic("KeyFunc is mandatory")
	}

	if options.SigningMethod == nil {
		options.SigningMethod = jwt.SigningMethodHS256
	}

	// verify if a Extractor is defined
	// if don't define a extractor use the default implementation
	// "extractTokenFromHEADER"
	if options.Extractor == nil {
		options.Extractor = extractTokenFromHEADER
	}

	return &JwtMiddleware{options}
}

// middleware for negroni
func (middleware *JwtMiddleware) HandlerJWT(
	w http.ResponseWriter,
	r *http.Request,
	next http.HandlerFunc) {

	err := proccess(w, r, &middleware.options)

	// If there was an error or dont exist a next, do not call next function.
	if err == nil && next != nil {
		next(w, r)
	}
}

// proccess excute the logic flow to extract and store the JWT object
func proccess(w http.ResponseWriter, r *http.Request, options *Options) error {
	// if the request method is options return nil
	// OPTIONS method is used from browser from security reasons.
	if strings.ToLower(r.Method) == "options" {
		return nil
	}

	token, err := options.Extractor(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	// token is empty send a empty JWT token to Store method
	if token == "" {
		err = options.Store(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
		return err
	}

	jwtToken, err := jwt.Parse(token, options.KeyFunc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	// validate the JWT token
	if options.SigningMethod.Alg() != jwtToken.Header["alg"] || !jwtToken.Valid {
		http.Error(w, "invalid JWT token", http.StatusUnauthorized)
	}

	err = options.Store(w, r, jwtToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}

	return err
}

// extractTokenFromHEADER find the Authorization fild in HTTP HEADER.
// The Authorization example:
// Authorization: Bearer <token>
func extractTokenFromHEADER(r *http.Request) (string, error) {
	// get Authorization from HEADER
	auth := r.Header.Get("Authorization")

	// verify if is empty
	if auth == "" {
		return "", nil
	}

	// validate the Authorization HEAD format
	regex := regexp.MustCompile(`(?i)(bearer)( +)([\w-]+)`)
	if !regex.MatchString(auth) {
		msg := "Invalid Authorization header format. Authorization: Bearer <token>"
		return "", errors.New(msg)
	}

	return regex.FindStringSubmatch(auth)[3], nil
}
