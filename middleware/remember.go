package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"myapp/data"
)

func (m *Middleware) CheckRemember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.App.Session.Exists(r.Context(), "userID") {
			// user is not logged in
			cookie, err := r.Cookie(fmt.Sprintf("_%s_remember", m.App.AppName))
			if err != nil {
				// no cookie, so go next
				next.ServeHTTP(w, r)
			} else {
				// we found a cokie, check it
				key := cookie.Value
				var u data.User
				if len(key) > 0 {
					// cookie has some data, validate it
					split := strings.Split(key, "|")
					uid, hash := split[0], split[1]
					id, _ := strconv.Atoi(uid)
					validHash := u.CheckForRememberToken(id, hash)
					if !validHash {
						m.deleteRememberCookie(w, r)
						m.App.Session.Put(r.Context(), "error", "You've been logged out from another device")
						next.ServeHTTP(w, r)
					} else {
						// valid hash, so log the user in
						user, _ := u.Get(id)
						m.App.Session.Put(r.Context(), "userID", user.ID)
						m.App.Session.Put(r.Context(), "remember_token", hash)
						next.ServeHTTP(w, r)
					}
				} else {
					// key length is zero, so it's probably a leftover cookie (user has not closed browser)
					m.deleteRememberCookie(w, r)
					next.ServeHTTP(w, r)
				}
			}
		} else {
			// user is logged in
			next.ServeHTTP(w, r)
		}
	})
}

func (m *Middleware) deleteRememberCookie(w http.ResponseWriter, r *http.Request) {
	_ = m.App.Session.RenewToken(r.Context())
	// delete the cookie
	newCookie := http.Cookie{
		Name:     fmt.Sprintf("_%s_remember", m.App.AppName),
		Value:    "",
		Path:     "/",
		Domain:   m.App.Session.Cookie.Domain,
		Expires:  time.Time{},
		MaxAge:   -1,
		Secure:   m.App.Session.Cookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &newCookie)

	// log the user out
	m.App.Session.Remove(r.Context(), "userID")
	_ = m.App.Session.Destroy(r.Context())
	_ = m.App.Session.RenewToken(r.Context())
}
