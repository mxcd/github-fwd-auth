package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/github-fwd-auth/internal/github"
	"github.com/mxcd/github-fwd-auth/internal/session"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type OAuthHandler struct {
	OAuthConfig *oauth2.Config
	Urls        *OAuthUrls
	Options     *OAuthHandlerOptions
}

type OAuthUrls struct {
	CallbackUrl string
	LoginUrl    string
	UserinfoUrl string
}

type OAuthHandlerOptions struct {
	OAuthConfig        *oauth2.Config
	GitHubConnector    *github.GitHubConnector
	SessionStore       *session.SessionStore
	OAuthPathPrefix    string
	ApplicationBaseUrl string
}

func NewOAuthHandler(options *OAuthHandlerOptions) *OAuthHandler {
	if options.OAuthPathPrefix == "" {
		options.OAuthPathPrefix = "/auth"
	} else {
		options.OAuthPathPrefix = "/" + strings.Trim(options.OAuthPathPrefix, "/")
	}

	urls := &OAuthUrls{
		CallbackUrl: options.OAuthPathPrefix + "/callback",
		LoginUrl:    options.OAuthPathPrefix + "/login",
		UserinfoUrl: options.OAuthPathPrefix + "/userinfo",
	}

	return &OAuthHandler{
		Options: options,
		Urls:    urls,
	}
}

func (o *OAuthHandler) HandleOAuth(c *gin.Context) (err error, handled bool) {
	if c.Request.URL.Path == "/favicon.ico" {
		return nil, true
	}

	if c.Request.URL.Path == o.Urls.CallbackUrl {
		o.handleCallback(c)
		return nil, true
	} else if c.Request.URL.Path == o.Urls.LoginUrl {
		o.handleLogin(c)
		return nil, true
	} else if c.Request.URL.Path == o.Urls.UserinfoUrl {
		o.handleUserinfo(c)
		return nil, true
	}

	return nil, false
}

func (o *OAuthHandler) handleCallback(c *gin.Context) {
	log.Debug().Msg("Handling OAuth callback")
	err := validateOAuthState(c)
	if err != nil {
		// request abort handled by validateOAuthState
		return
	}

	log.Trace().Msg("oauth state is valid. exchanging token exchange")

	oauthToken, err := o.doTokenExchange(c)
	if err != nil {
		// request abort handled by doTokenExchange
		return
	}

	log.Trace().Msg("token exchange successful")

	session, err := o.Options.SessionStore.CreateSession(c)
	if err != nil {
		log.Error().Err(err).Msg("failed to create session")
		c.Status(http.StatusInternalServerError)
		c.Abort()
		return
	}

	tokenSource := o.Options.OAuthConfig.TokenSource(c.Request.Context(), oauthToken)
	session.OAuthTokenSource = &tokenSource

	userInformation, err := o.getUserInformation(c, session.GetHttpClient())
	if err != nil {
		// request abort handled by getUserInformation
		return
	}

	log.Debug().Msg("saving session with user information")
	session.UserInformation = userInformation
	o.Options.SessionStore.Save(c, session)
	c.Set("session", session)

	log.Debug().Msg("redirecting to /")
	// TODO redirect to original URL
	c.Redirect(http.StatusTemporaryRedirect, o.Options.ApplicationBaseUrl)
	c.Next()
}

func (o *OAuthHandler) handleLogin(c *gin.Context) {
	log.Debug().Msg("Handling OAuth login redirect")
	oauthState := generateStateOauthCookie(c.Writer)
	oidcProviderRedirectUrl := o.Options.OAuthConfig.AuthCodeURL(oauthState)
	c.Redirect(http.StatusTemporaryRedirect, oidcProviderRedirectUrl)
	c.Abort()
}

func (o *OAuthHandler) handleUserinfo(c *gin.Context) {

}

func (o *OAuthHandler) HandleUiAuthentication(c *gin.Context) error {
	session, err := o.CheckAuthentication(c)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s%s", o.Options.ApplicationBaseUrl, o.Urls.LoginUrl))
		c.Abort()
		return err
	}
	c.Set("session", session)
	return nil
}

func (o *OAuthHandler) HandleApiAuthentication(c *gin.Context) error {
	session, err := o.CheckAuthentication(c)
	if err != nil {
		c.Status(http.StatusUnauthorized)
		c.Abort()
		return err
	}
	c.Set("session", session)
	return nil
}

func (o *OAuthHandler) CheckAuthentication(c *gin.Context) (*session.Session, error) {

	// if h.config.ApiKeyHandler != nil {
	//   handled := h.config.ApiKeyHandler(c)
	//   if handled {
	//     log.Trace().Msg("api key handler passed request")
	//     return
	//   }
	// }

	session, ok := o.Options.SessionStore.GetSession(c)
	if !ok {
		log.Debug().Msg("no session found for request. redirecting to login handler")
		return session, errors.New("no session found for request")
	}

	return session, nil

	// checkForAllowedTeam := func() error {
	//   sessionTeams := session.UserInformation.Teams
	//   teamSlugs := github.GetTeamSlugs(sessionTeams)

	//   for _, allowedTeam := range h.config.AllowedTeams {
	//     if slices.Contains(teamSlugs, allowedTeam) {
	//       c.Next()
	//       return nil
	//     }
	//   }
	//   return errors.New("user is not member of any of the allowed teams: [" + strings.Join(h.config.AllowedTeams, ", ") + "]")
	// }

	// log.Trace().Msg("checking if user is member of allowed teams")
	// err := checkForAllowedTeam()
	// if err == nil {
	// 	log.Trace().Msg("user is member of allowed teams. pass")
	// 	return
	// }

	// log.Debug().Msg("user is not member of any of the allowed teams. re-querying user information")
	// userInformation, err := h.getUserInformation(c, session.GetHttpClient())
	// if err != nil {
	// 	// request abort handled by getUserInformation
	// 	return
	// }
	// session.UserInformation = userInformation

	// log.Trace().Msg("re-checking if user is member of allowed teams")
	// err = checkForAllowedTeam()
	// if err == nil {
	// 	log.Trace().Msg("user is member of allowed teams. pass")
	// 	return
	// }

}
