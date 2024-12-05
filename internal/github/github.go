package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	config *GitHubConnectorConfig
}

type GitHubConnectorConfig struct {
	ApiBaseUrl string
}

func NewGitHubConnector(config *GitHubConnectorConfig) *GitHubConnector {
	return &GitHubConnector{
		config: config,
	}
}

func (g *GitHubConnector) GetUserProfile(client *http.Client) (*UserProfile, error) {
	body, err := g.doGetRequest(client, "/user")
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

func (g *GitHubConnector) GetUserTeams(client *http.Client) (*[]Team, error) {
	body, err := g.doGetRequest(client, "/user/teams")
	if err != nil {
		return nil, err
	}

	var teams []Team
	err = json.Unmarshal(body, &teams)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal teams")
		return nil, err
	}
	return &teams, nil
}

func (g *GitHubConnector) GetUserInformation(client *http.Client) (*UserInformation, error) {
	userProfile, err := g.GetUserProfile(client)
	if err != nil {
		return nil, err
	}

	teams, err := g.GetUserTeams(client)
	if err != nil {
		return nil, err
	}

	return &UserInformation{
		Profile: userProfile,
		Teams:   teams,
	}, nil
}

func (g *GitHubConnector) doGetRequest(client *http.Client, path string) ([]byte, error) {
	requestURL := g.config.ApiBaseUrl + path
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
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

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error().Err(err).Str("request url", requestURL).Msg("failed to read http response body")
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		log.Error().Err(err).Int("status", res.StatusCode).Str("request url", requestURL).Msg("http response status not ok")
		return nil, fmt.Errorf("http response status not ok")
	}

	return body, nil
}

func GetTeamSlugs(teams *[]Team) []string {
	slugs := make([]string, len(*teams))
	for i, team := range *teams {
		slugs[i] = team.Organization.Login + "/" + team.Slug
	}
	return slugs
}
