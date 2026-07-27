package policy

import (
	"sort"
	"strings"
)

// Built-in URL categories for web filtering. Categories drive actions
// (block / allow / isolate) so RBI sits *behind* URL filtering:
// known-bad is blocked, trusted is allowed direct, the rest can be isolated.
//
// Matching is hostname suffix based (example.com matches www.example.com).
// Category "uncategorized" matches hosts that are not in any other category.

// Category is a named URL filter group.
type Category struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	// Domains are suffix matchers (no leading dot). Empty for uncategorized.
	Domains []string `json:"domains,omitempty"`
	// Special is true for synthetic categories (e.g. uncategorized).
	Special bool `json:"special,omitempty"`
}

// Categories is the built-in catalog (immutable for v1).
var Categories = []Category{
	{
		ID:          "malware",
		Name:        "Malware & phishing",
		Description: "Known-bad / high-confidence malicious destinations. Action: Block.",
		Domains: []string{
			// Illustrative lab list — replace with threat feed in production.
			"malware.testing.google.test",
			"testsafebrowsing.appspot.com",
			"ianfette.org",
			"malware.wicar.org",
			"eicar.org",
			"secure.eicar.org",
		},
	},
	{
		ID:          "adult",
		Name:        "Adult content",
		Description: "Adult / pornography categories. Default: Block.",
		Domains: []string{
			"pornhub.com",
			"xvideos.com",
			"xnxx.com",
			"xhamster.com",
			"onlyfans.com",
		},
	},
	{
		ID:          "gambling",
		Name:        "Gambling",
		Description: "Online gambling. Default: Isolate (RBI).",
		Domains: []string{
			"bet365.com",
			"pokerstars.com",
			"draftkings.com",
			"fanduel.com",
			"888.com",
		},
	},
	{
		ID:          "social_media",
		Name:        "Social media",
		Description: "Consumer social networks. Default: Isolate (RBI).",
		Domains: []string{
			"facebook.com",
			"fb.com",
			"instagram.com",
			"twitter.com",
			"x.com",
			"tiktok.com",
			"snapchat.com",
			"reddit.com",
			"pinterest.com",
			"linkedin.com",
		},
	},
	{
		ID:          "streaming",
		Name:        "Streaming & entertainment",
		Description: "Video/music streaming. Default: Isolate (RBI).",
		Domains: []string{
			"netflix.com",
			"youtube.com",
			"youtu.be",
			"twitch.tv",
			"hulu.com",
			"disneyplus.com",
			"spotify.com",
		},
	},
	{
		ID:          "trusted_productivity",
		Name:        "Trusted productivity",
		Description: "Common business SaaS. Default: Allow direct (no RBI), malware on.",
		Domains: []string{
			"microsoft.com",
			"office.com",
			"office365.com",
			"microsoftonline.com",
			"live.com",
			"outlook.com",
			"sharepoint.com",
			"onedrive.com",
			"google.com",
			"google.co.il",
			"googleapis.com",
			"gstatic.com",
			"gmail.com",
			"docs.google.com",
			"drive.google.com",
			"slack.com",
			"zoom.us",
			"webex.com",
			"atlassian.com",
			"github.com",
			"githubusercontent.com",
			"gitlab.com",
			"okta.com",
			"salesforce.com",
			"force.com",
			"servicenow.com",
			"box.com",
			"dropbox.com",
			"adobe.com",
			"notion.so",
		},
	},
	{
		ID:          "news_media",
		Name:        "News & media",
		Description: "News sites. Default: Isolate (RBI) — high script risk.",
		Domains: []string{
			"ynet.co.il",
			"walla.co.il",
			"mako.co.il",
			"haaretz.com",
			"haaretz.co.il",
			"cnn.com",
			"bbc.com",
			"bbc.co.uk",
			"nytimes.com",
			"theguardian.com",
			"reuters.com",
		},
	},
	{
		ID:          "uncategorized",
		Name:        "Uncategorized",
		Description: "Hosts not listed in any other category. Default: Isolate (RBI).",
		Special:     true,
	},
}

// CategoryByID returns a category or false.
func CategoryByID(id string) (Category, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, c := range Categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// CategoryIDs returns sorted category ids.
func CategoryIDs() []string {
	out := make([]string, 0, len(Categories))
	for _, c := range Categories {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

// HostInCategory reports whether host matches the category (suffix match).
// For "uncategorized", true when host is non-empty and not in any non-special category.
func HostInCategory(host, categoryID string) bool {
	host = normalizeCategoryHost(host)
	if host == "" {
		return false
	}
	categoryID = strings.ToLower(strings.TrimSpace(categoryID))
	if categoryID == "uncategorized" {
		return !hostInAnyConcreteCategory(host)
	}
	cat, ok := CategoryByID(categoryID)
	if !ok || cat.Special {
		return false
	}
	return hostMatchesDomainList(host, cat.Domains)
}

func hostInAnyConcreteCategory(host string) bool {
	for _, c := range Categories {
		if c.Special {
			continue
		}
		if hostMatchesDomainList(host, c.Domains) {
			return true
		}
	}
	return false
}

func hostMatchesDomainList(host string, domains []string) bool {
	for _, d := range domains {
		d = normalizeCategoryHost(d)
		if d == "" {
			continue
		}
		if domainSuffixMatch(host, d) {
			return true
		}
	}
	return false
}

func normalizeCategoryHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	return h
}

// CategoriesForHost returns all concrete category IDs matching host (not uncategorized).
func CategoriesForHost(host string) []string {
	host = normalizeCategoryHost(host)
	if host == "" {
		return nil
	}
	var out []string
	for _, c := range Categories {
		if c.Special {
			continue
		}
		if hostMatchesDomainList(host, c.Domains) {
			out = append(out, c.ID)
		}
	}
	if len(out) == 0 {
		return []string{"uncategorized"}
	}
	return out
}
