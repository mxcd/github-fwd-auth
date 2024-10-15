package util

import "github.com/mxcd/go-config/config"

func InitConfig() error {
	err := config.LoadConfigWithOptions([]config.Value{
		config.String("LOG_LEVEL").NotEmpty().Default("info"),
		config.Bool("DEV").Default(false),
		config.Int("PORT").Default(8080),

		config.String("GITHUB_API_BASE_URL").Default("https://api.github.com").NotEmpty(),

		config.String("OAUTH_CLIENT_ID").NotEmpty(),
		config.String("OAUTH_CLIENT_SECRET").NotEmpty().Sensitive(),
		config.String("OAUTH_REDIRECT_URI").NotEmpty(),
		config.String("OAUTH_PROVIDER_AUTH_URL").NotEmpty(),
		config.String("OAUTH_PROVIDER_TOKEN_URL").NotEmpty(),
		config.String("OAUTH_PROVIDER_DEVICE_AUTH_URL").NotEmpty(),
		config.String("OAUTH_SCOPES").NotEmpty(),

		config.StringArray("ALLOWED_GITHUB_TEAMS").Default([]string{}),

		config.Bool("CREATE_JWT").Default(false),
		config.String("JWT_ALGORITHM").Default("RS512"),
		config.String("JWT_PRIVATE_KEY").Sensitive(),
		config.String("JWT_ISSUER"),

		config.StringArray("API_KEYS").Sensitive().Default([]string{}),

		config.String("BASE_URL").NotEmpty().Default("http://localhost:8080"),
		config.String("COOKIE_DOMAIN").NotEmpty().Default("localhost"),
		config.String("SESSION_COOKIE_NAME").NotEmpty().Default("session_id"),
		config.Int("SESSION_MAX_AGE").Default(3600 * 24 * 7),
		config.String("SESSION_STORAGE_BACKEND").NotEmpty().Default("memory"),
	}, &config.LoadConfigOptions{
		DotEnvFile: "github-fwd-auth.env",
	})
	return err
}
