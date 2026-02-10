package main

import (
	"strings"

	"github.com/rs/zerolog/log"

	githuboauth "github.com/mxcd/github-fwd-auth/pkg/githuboauth"

	"github.com/mxcd/github-fwd-auth/internal/server"
	"github.com/mxcd/github-fwd-auth/internal/util"
	"github.com/mxcd/github-fwd-auth/pkg/jwt"
	"github.com/mxcd/go-config/config"
)

func main() {
	err := util.InitConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to initialize config")
	}
	config.Print()
	util.InitLogger(util.NewLoggerOptionsFromEnv())

	// JWT signer (optional)
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

	// Decode session keys from base64
	sessionSecretKey, err := githuboauth.DecodeKeyFromBase64(config.Get().String("SESSION_SECRET_KEY"))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to decode SESSION_SECRET_KEY")
	}
	sessionEncryptionKey, err := githuboauth.DecodeKeyFromBase64(config.Get().String("SESSION_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to decode SESSION_ENCRYPTION_KEY")
	}

	sessionMaxAge := config.Get().Int("SESSION_MAX_AGE")

	// Initialize GitHub OAuth library (without middleware registration)
	oauthHandle, err := githuboauth.New(&githuboauth.Config{
		ClientID:             config.Get().String("OAUTH_CLIENT_ID"),
		ClientSecret:         config.Get().String("OAUTH_CLIENT_SECRET"),
		RedirectURI:          config.Get().String("OAUTH_REDIRECT_URI"),
		Scopes:               strings.Split(config.Get().String("OAUTH_SCOPES"), ","),
		AuthURL:              config.Get().String("OAUTH_PROVIDER_AUTH_URL"),
		TokenURL:             config.Get().String("OAUTH_PROVIDER_TOKEN_URL"),
		DeviceAuthURL:        config.Get().String("OAUTH_PROVIDER_DEVICE_AUTH_URL"),
		GitHubAPIBaseURL:     config.Get().String("GITHUB_API_BASE_URL"),
		AllowedTeams:         config.Get().StringArray("ALLOWED_GITHUB_TEAMS"),
		AdminTeams:           config.Get().StringArray("ADMIN_GITHUB_TEAMS"),
		AllowedAPIKeys:       config.Get().StringArray("API_KEYS"),
		SessionSecretKey:     sessionSecretKey,
		SessionEncryptionKey: sessionEncryptionKey,
		SessionMaxAge:        &sessionMaxAge,
		CookieName:           config.Get().String("SESSION_COOKIE_NAME"),
		CookieDomain:         config.Get().String("COOKIE_DOMAIN"),
		CookieInsecure:       config.Get().Bool("COOKIE_INSECURE"),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize github oauth")
	}

	s := server.NewServer(&server.ServerOptions{
		Port:        config.Get().Int("PORT"),
		JwtSigner:   jwtSigner,
		OAuthHandle: oauthHandle,
	})

	if err := s.Run(); err != nil {
		log.Fatal().Err(err).Msg("unable to start http server")
	}
}
