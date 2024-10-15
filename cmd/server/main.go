package main

import (
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"

	"github.com/mxcd/github-fwd-auth/internal/github"
	"github.com/mxcd/github-fwd-auth/internal/oauth"
	"github.com/mxcd/github-fwd-auth/internal/server"
	"github.com/mxcd/github-fwd-auth/internal/session"
	"github.com/mxcd/github-fwd-auth/internal/util"
	"github.com/mxcd/github-fwd-auth/pkg/jwt"
	"github.com/mxcd/go-config/config"
)

func main() {
	err := util.InitConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to initialize job management config")
	}
	config.Print()

	util.InitLogger(util.NewLoggerOptionsFromEnv())

	var jwtSigner *jwt.Signer
	if config.Get().Bool("CREATE_JWT") {
		jwtSigner, err = jwt.NewSigner(&jwt.SignerOptions{
			Algorithm:     config.Get().String("JWT_ALGORITHM"),
			JwtPrivateKey: config.Get().String("JWT_PRIVATE_KEY"),
			JwtIssuer:     config.Get().String("JWT_ISSUER"),
		})
		if err != nil {
			log.Fatal().Err(err).Msg("error initializing jwt signer")
		}
	}

	oauthConfig := &oauth2.Config{
		RedirectURL:  config.Get().String("OAUTH_REDIRECT_URI"),
		ClientID:     config.Get().String("OAUTH_CLIENT_ID"),
		ClientSecret: config.Get().String("OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Get().String("OAUTH_SCOPES"), ","),
		Endpoint: oauth2.Endpoint{
			AuthURL:       config.Get().String("OAUTH_PROVIDER_AUTH_URL"),
			TokenURL:      config.Get().String("OAUTH_PROVIDER_TOKEN_URL"),
			DeviceAuthURL: config.Get().String("OAUTH_PROVIDER_DEVICE_AUTH_URL"),
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}

	githubConnector := github.NewGitHubConnector(&github.GitHubConnectorConfig{
		ApiBaseUrl: config.Get().String("GITHUB_API_BASE_URL"),
	})

	sessionStore := session.NewSessionStore(session.GetSessionStoreConfig())

	oauthHandler := oauth.NewOAuthHandler(&oauth.OAuthHandlerOptions{
		OAuthConfig:        oauthConfig,
		OAuthPathPrefix:    "/auth",
		ApplicationBaseUrl: config.Get().String("BASE_URL"),
		GitHubConnector:    githubConnector,
		SessionStore:       sessionStore,
	})

	serverOptions := &server.ServerOptions{
		Port:         config.Get().Int("PORT"),
		ApiKeys:      config.Get().StringArray("API_KEYS"),
		JwtSigner:    jwtSigner,
		OAuthHandler: oauthHandler,
		SessionStore: sessionStore,
		AllowedTeams: config.Get().StringArray("ALLOWED_GITHUB_TEAMS"),
	}

	s := server.NewServer(serverOptions)

	err = s.Run()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to start http server")
	}
}
