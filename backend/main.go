package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

type AppClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

func main() {
	// ---- config (use env vars) ----
	googleClientID := mustEnv("GOOGLE_CLIENT_ID")
	googleClientSecret := mustEnv("GOOGLE_CLIENT_SECRET")
	googleCallbackURL := mustEnv("GOOGLE_CALLBACK_URL") // e.g. http://localhost:8080/auth/google/callback
	jwtSecret := []byte(mustEnv("JWT_SECRET"))

	// ---- goth providers ----
	goth.UseProviders(
		google.New(googleClientID, googleClientSecret, googleCallbackURL, "email", "profile"),
	)

	// ---- gothic session store (used internally for OAuth flow + we store "redirect") ----
	// Goth docs note you can override gothic.Store (cookie options, secure, etc.) :contentReference[oaicite:4]{index=4}
	store := sessions.NewCookieStore([]byte(mustEnv("SESSION_SECRET")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false,                // set true in prod (https)
		SameSite: http.SameSiteLaxMode, // good default for localhost dev
	}
	gothic.Store = store

	r := gin.Default()

	// --- AUTH ROUTES ---
	r.GET("/auth/:provider", func(c *gin.Context) {
		provider := c.Param("provider")

		// Provide the provider name to gothic via request context
		// (gothic expects provider from query or ":provider"; this helper supports context injection) :contentReference[oaicite:5]{index=5}
		c.Request = gothic.GetContextWithProvider(c.Request, provider)

		// Optional: remember where to send the browser after login
		redirectTo := c.Query("redirect")
		if redirectTo == "" {
			redirectTo = "http://localhost:5173/"
		}
		_ = gothic.StoreInSession("redirect", redirectTo, c.Request, c.Writer) // :contentReference[oaicite:6]{index=6}

		gothic.BeginAuthHandler(c.Writer, c.Request) // redirects to Google
	})

	r.GET("/auth/:provider/callback", func(c *gin.Context) {
		provider := c.Param("provider")
		c.Request = gothic.GetContextWithProvider(c.Request, provider)

		// Completes OAuth + fetches basic user info from provider :contentReference[oaicite:7]{index=7}
		u, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Create our own app token (JWT) – do NOT send Google tokens to the frontend
		claims := AppClaims{
			Email: u.Email,
			Name:  u.Name,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign token"})
			return
		}

		// HttpOnly cookie (frontend JS can't read it)
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "auth",
			Value:    signed,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,                // true in prod (https)
			SameSite: http.SameSiteLaxMode, // see note below for cross-site setups
			MaxAge:   86400 * 7,
		})

		redirectTo, _ := gothic.GetFromSession("redirect", c.Request) // :contentReference[oaicite:8]{index=8}
		if redirectTo == "" {
			redirectTo = "http://localhost:5173/"
		}
		http.Redirect(c.Writer, c.Request, redirectTo, http.StatusFound)
	})

	r.GET("/logout", func(c *gin.Context) {
		// clear our cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "auth",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
			SameSite: http.SameSiteLaxMode,
		})
		c.Status(http.StatusNoContent)
	})

	// --- API ROUTE to test login ---
	r.GET("/api/me", func(c *gin.Context) {
		cookie, err := c.Request.Cookie("auth")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not signed in"})
			return
		}

		tok, err := jwt.ParseWithClaims(cookie.Value, &AppClaims{}, func(token *jwt.Token) (any, error) {
			return jwtSecret, nil
		})
		if err != nil || !tok.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims := tok.Claims.(*AppClaims)
		c.JSON(http.StatusOK, gin.H{"email": claims.Email, "name": claims.Name})
	})

	log.Println("Backend on http://localhost:8080")
	r.Run(":8080")
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		panic("missing env var: " + k)
	}
	return v
}
