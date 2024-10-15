package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/mxcd/github-fwd-auth/internal/github"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func validateOAuthState(c *gin.Context) error {
	oauthState, err := c.Cookie("oauthstate")
	if err != nil {
		log.Warn().Err(err).Msg("failed to get oauth state from cookie")
		c.Status(http.StatusUnauthorized)
		c.Writer.Write([]byte("failed to get oauth state from cookie"))
		c.Abort()
		return err
	}
	if c.Request.FormValue("state") != oauthState {
		msg := "invalid oauth state"
		log.Warn().Msg(msg)
		c.Status(http.StatusUnauthorized)
		c.Writer.Write([]byte(msg))
		c.Abort()
		return errors.New(msg)
	}
	return nil
}

func (h *OAuthHandler) doTokenExchange(c *gin.Context) (*oauth2.Token, error) {
	code := c.Request.FormValue("code")
	log.Trace().Str("code", code).Msg("doing token exchange")
	oauthToken, err := h.Options.OAuthConfig.Exchange(c.Request.Context(), code)
	if err != nil {
		log.Error().Err(err).Msg("failed to exchange code")
		c.Status(http.StatusUnauthorized)
		c.Writer.Write([]byte("failed to exchange code"))
		c.Abort()
		return nil, err
	}
	log.Trace().Msg("token exchange successful")
	return oauthToken, nil
}

func (h *OAuthHandler) getUserInformation(c *gin.Context, client *http.Client) (*github.UserInformation, error) {
	log.Trace().Msg("getting user information")
	userInformation, err := h.Options.GitHubConnector.GetUserInformation(client)
	if err != nil {
		log.Error().Err(err).Msg("failed to get user information")
		c.Status(http.StatusInternalServerError)
		c.Abort()
		return nil, err
	}
	return userInformation, nil
}