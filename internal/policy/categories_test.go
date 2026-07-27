package policy

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHostInCategory(t *testing.T) {
	if !HostInCategory("www.microsoft.com", "trusted_productivity") {
		t.Fatal("microsoft should be trusted_productivity")
	}
	if !HostInCategory("chat.openai.com", "uncategorized") {
		// chat.openai.com not in trusted list
		t.Fatal("unknown host should be uncategorized")
	}
	if HostInCategory("microsoft.com", "uncategorized") {
		t.Fatal("trusted host must not be uncategorized")
	}
	if !HostInCategory("news.ynet.co.il", "news_media") {
		t.Fatal("ynet subdomain should match news_media")
	}
	if !HostInCategory("eicar.org", "malware") {
		t.Fatal("eicar should be malware category")
	}
}

func TestURLFilterThenRBIStack(t *testing.T) {
	// Layered rules: block malware → allow trusted (not isolated) → isolate uncategorized
	rules := []Rule{
		{
			ID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Name: "block-malware",
			Enabled: true, Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionBlock,
					Destinations: []Condition{{Type: CondURLCategory, Value: "malware"}},
					TLSIntercept: true,
				},
			},
		},
		{
			ID: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Name: "allow-trusted",
			Enabled: true, Priority: 20,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					Destinations: []Condition{{Type: CondURLCategory, Value: "trusted_productivity"}},
					TLSIntercept: true,
				},
				RBI:         RBISection{Mode: RBINotIsolated},
				Antimalware: AntimalwareSection{Enabled: true},
			},
		},
		{
			ID: uuid.MustParse("00000000-0000-4000-8000-000000000003"), Name: "isolate-uncat",
			Enabled: true, Priority: 30,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					Destinations: []Condition{{Type: CondURLCategory, Value: "uncategorized"}},
					TLSIntercept: true,
				},
				RBI: RBISection{Mode: RBIIsolated, BlockCopyFromSite: true},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	var eng Engine
	eng.Swap(snap)

	// Malware blocked
	u, _ := url.Parse("https://eicar.org/download")
	d := eng.Evaluate(RequestInput{ClientIP: net.ParseIP("10.0.0.1"), URL: u, Method: "GET", Now: time.Now()})
	if d.FinalAction != ActionBlock {
		t.Fatalf("malware action=%s", d.FinalAction)
	}
	if d.RBIIsolated {
		t.Fatal("blocked malware should not isolate")
	}

	// Trusted: allow, not isolated (locked), even though uncategorized rule would isolate
	u2, _ := url.Parse("https://docs.google.com/document")
	d2 := eng.Evaluate(RequestInput{ClientIP: net.ParseIP("10.0.0.1"), URL: u2, Method: "GET", Now: time.Now()})
	if d2.FinalAction != ActionAllow {
		t.Fatalf("trusted action=%s", d2.FinalAction)
	}
	if d2.RBIIsolated {
		t.Fatal("trusted productivity must lock RBI off (first explicit not_isolated wins)")
	}
	if !d2.MalwareScan {
		t.Fatal("trusted should still scan malware")
	}

	// Uncategorized: isolate
	u3, _ := url.Parse("https://some-random-blog.example/")
	d3 := eng.Evaluate(RequestInput{ClientIP: net.ParseIP("10.0.0.1"), URL: u3, Method: "GET", Now: time.Now()})
	if d3.FinalAction != ActionAllow || !d3.RBIIsolated {
		t.Fatalf("uncategorized want allow+isolate got action=%s rbi=%v cats=%v", d3.FinalAction, d3.RBIIsolated, d3.URLCategories)
	}
	if !d3.TLSIntercept {
		t.Fatal("isolation implies TLS intercept")
	}
}

func TestCompileURLCategoryAlias(t *testing.T) {
	rules := []Rule{{
		ID: uuid.New(), Name: "c", Enabled: true, Priority: 1,
		Sections: RuleSections{
			General: GeneralSection{
				Action:       ActionBlock,
				Destinations: []Condition{{Type: "category", Value: "adult"}},
			},
		},
	}}
	if _, err := Compile(rules, nil); err != nil {
		t.Fatal(err)
	}
}
