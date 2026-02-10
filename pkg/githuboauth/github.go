package githuboauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

type Organization struct {
	Login                   string `json:"login"`
	ID                      int    `json:"id"`
	NodeID                  string `json:"node_id"`
	URL                     string `json:"url"`
	ReposURL                string `json:"repos_url"`
	EventsURL               string `json:"events_url"`
	HooksURL                string `json:"hooks_url"`
	IssuesURL               string `json:"issues_url"`
	MembersURL              string `json:"members_url"`
	PublicMembersURL        string `json:"public_members_url"`
	AvatarURL               string `json:"avatar_url"`
	Description             string `json:"description"`
	Name                    string `json:"name"`
	Company                 string `json:"company"`
	Blog                    string `json:"blog"`
	Location                string `json:"location"`
	Email                   string `json:"email"`
	IsVerified              bool   `json:"is_verified"`
	HasOrganizationProjects bool   `json:"has_organization_projects"`
	HasRepositoryProjects   bool   `json:"has_repository_projects"`
	PublicRepos             int    `json:"public_repos"`
	PublicGists             int    `json:"public_gists"`
	Followers               int    `json:"followers"`
	Following               int    `json:"following"`
	HTMLURL                 string `json:"html_url"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
	Type                    string `json:"type"`
}

type Team struct {
	ID                  int          `json:"id"`
	NodeID              string       `json:"node_id"`
	URL                 string       `json:"url"`
	HTMLURL             string       `json:"html_url"`
	Name                string       `json:"name"`
	Slug                string       `json:"slug"`
	Description         string       `json:"description"`
	Privacy             string       `json:"privacy"`
	NotificationSetting string       `json:"notification_setting"`
	Permission          string       `json:"permission"`
	MembersURL          string       `json:"members_url"`
	RepositoriesURL     string       `json:"repositories_url"`
	Parent              *Team        `json:"parent"`
	MembersCount        int          `json:"members_count"`
	ReposCount          int          `json:"repos_count"`
	CreatedAt           string       `json:"created_at"`
	UpdatedAt           string       `json:"updated_at"`
	Organization        Organization `json:"organization"`
}

type Plan struct {
	Name          string `json:"name"`
	Space         int    `json:"space"`
	PrivateRepos  int    `json:"private_repos"`
	Collaborators int    `json:"collaborators"`
}

type UserProfile struct {
	Login                   string `json:"login"`
	ID                      int    `json:"id"`
	NodeID                  string `json:"node_id"`
	AvatarURL               string `json:"avatar_url"`
	GravatarID              string `json:"gravatar_id"`
	URL                     string `json:"url"`
	HTMLURL                 string `json:"html_url"`
	FollowersURL            string `json:"followers_url"`
	FollowingURL            string `json:"following_url"`
	GistsURL                string `json:"gists_url"`
	StarredURL              string `json:"starred_url"`
	SubscriptionsURL        string `json:"subscriptions_url"`
	OrganizationsURL        string `json:"organizations_url"`
	ReposURL                string `json:"repos_url"`
	EventsURL               string `json:"events_url"`
	ReceivedEventsURL       string `json:"received_events_url"`
	Type                    string `json:"type"`
	SiteAdmin               bool   `json:"site_admin"`
	Name                    string `json:"name"`
	Company                 string `json:"company"`
	Blog                    string `json:"blog"`
	Location                string `json:"location"`
	Email                   string `json:"email"`
	Hireable                bool   `json:"hireable"`
	Bio                     string `json:"bio"`
	TwitterUsername         string `json:"twitter_username"`
	PublicRepos             int    `json:"public_repos"`
	PublicGists             int    `json:"public_gists"`
	Followers               int    `json:"followers"`
	Following               int    `json:"following"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
	PrivateGists            int    `json:"private_gists"`
	TotalPrivateRepos       int    `json:"total_private_repos"`
	OwnedPrivateRepos       int    `json:"owned_private_repos"`
	DiskUsage               int    `json:"disk_usage"`
	Collaborators           int    `json:"collaborators"`
	TwoFactorAuthentication bool   `json:"two_factor_authentication"`
	Plan                    Plan   `json:"plan"`
}

type UserInformation struct {
	Profile *UserProfile
	Teams   *[]Team
}

type GitHubConnector struct {
	apiBaseURL string
}

type GitHubConnectorConfig struct {
	ApiBaseURL string
}

// NewGitHubConnector creates a new GitHubConnector with URL validation.
// The API base URL must use HTTPS to prevent credential leakage.
func NewGitHubConnector(config *GitHubConnectorConfig) (*GitHubConnector, error) {
	apiBaseURL := config.ApiBaseURL
	if apiBaseURL == "" {
		apiBaseURL = "https://api.github.com"
	}

	// F-03: Validate URL to prevent SSRF
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub API base URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("GitHub API base URL must use HTTPS, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("GitHub API base URL must include a host")
	}

	return &GitHubConnector{
		apiBaseURL: strings.TrimRight(apiBaseURL, "/"),
	}, nil
}

func (g *GitHubConnector) GetUserProfile(ctx context.Context, client *http.Client) (*UserProfile, error) {
	body, err := g.doGetRequest(ctx, client, "/user")
	if err != nil {
		return nil, err
	}

	var userProfile UserProfile
	err = json.Unmarshal(body, &userProfile)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal user profile")
		return nil, err
	}
	return &userProfile, nil
}

// F-A: Paginate through all pages of /user/teams to avoid missing teams
// when a user belongs to >30 teams (GitHub default page size).
func (g *GitHubConnector) GetUserTeams(ctx context.Context, client *http.Client) (*[]Team, error) {
	var allTeams []Team
	page := 1
	for {
		body, err := g.doGetRequest(ctx, client, "/user/teams", map[string]string{
			"per_page": "100",
			"page":     strconv.Itoa(page),
		})
		if err != nil {
			return nil, err
		}

		var teams []Team
		if err := json.Unmarshal(body, &teams); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal teams")
			return nil, err
		}
		allTeams = append(allTeams, teams...)
		if len(teams) < 100 {
			break
		}
		page++
		// Safety cap to prevent infinite loops against misbehaving APIs
		if page > 50 {
			log.Warn().Msg("team pagination exceeded 50 pages, stopping")
			break
		}
	}
	return &allTeams, nil
}

func (g *GitHubConnector) GetUserInformation(ctx context.Context, client *http.Client) (*UserInformation, error) {
	userProfile, err := g.GetUserProfile(ctx, client)
	if err != nil {
		return nil, err
	}

	teams, err := g.GetUserTeams(ctx, client)
	if err != nil {
		return nil, err
	}

	return &UserInformation{
		Profile: userProfile,
		Teams:   teams,
	}, nil
}

// F-D: Accept context and use http.NewRequestWithContext to propagate
// cancellation to outbound GitHub API calls.
func (g *GitHubConnector) doGetRequest(ctx context.Context, client *http.Client, path string, queryParams ...map[string]string) ([]byte, error) {
	// F-03: Use url.JoinPath instead of string concatenation to prevent path injection.
	// Query parameters must be passed separately to avoid url.JoinPath encoding '?' as '%3F'.
	requestURL, err := url.JoinPath(g.apiBaseURL, path)
	if err != nil {
		log.Error().Err(err).Str("base", g.apiBaseURL).Str("path", path).Msg("failed to construct request URL")
		return nil, fmt.Errorf("failed to construct request URL: %w", err)
	}

	// Append query parameters properly via url.Values
	if len(queryParams) > 0 && len(queryParams[0]) > 0 {
		u, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse request URL: %w", err)
		}
		q := u.Query()
		for k, v := range queryParams[0] {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		requestURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		log.Error().Err(err).Str("request url", requestURL).Msg("failed to create http request")
		return nil, err
	}

	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")

	res, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("request url", requestURL).Msg("failed to execute http request")
		return nil, err
	}
	defer res.Body.Close()

	// F-04: Check status code before reading full body to avoid wasting memory on error responses
	if res.StatusCode != http.StatusOK {
		// Read limited error body for logging context
		errBody, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		log.Error().Int("status", res.StatusCode).Str("request url", requestURL).Str("body", string(errBody)).Msg("http response status not ok")
		return nil, fmt.Errorf("http response status not ok: %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 10<<20))
	if err != nil {
		log.Error().Err(err).Str("request url", requestURL).Msg("failed to read http response body")
		return nil, err
	}

	return body, nil
}

// GetTeamSlugs returns team slugs in "org/team-slug" format, normalized to lowercase.
// F-07: Case-insensitive comparison — GitHub slugs are case-insensitive.
// F-08: Nil-safe — returns nil if teams is nil.
func GetTeamSlugs(teams *[]Team) []string {
	if teams == nil {
		return nil
	}
	slugs := make([]string, len(*teams))
	for i, team := range *teams {
		slugs[i] = strings.ToLower(team.Organization.Login + "/" + team.Slug)
	}
	return slugs
}
