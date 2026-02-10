package githuboauth

import "testing"

// F-14: Fuzz test for GetTeamSlugs to exercise parsing edge cases.
func FuzzGetTeamSlugs(f *testing.F) {
	f.Add("developers", "myorg")
	f.Add("", "")
	f.Add("team-with-dashes", "org-with-dashes")
	f.Add("UPPERCASE", "MixedCase")
	f.Add("a/b", "c/d")

	f.Fuzz(func(t *testing.T, slug, org string) {
		teams := &[]Team{
			{Slug: slug, Organization: Organization{Login: org}},
		}
		result := GetTeamSlugs(teams)
		if len(result) != 1 {
			t.Errorf("expected 1 team slug, got %d", len(result))
		}
	})
}
