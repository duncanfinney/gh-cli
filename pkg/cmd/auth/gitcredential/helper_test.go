package login

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/pkg/iostreams"
)

type tinyConfig map[string]string

func (c tinyConfig) ActiveToken(host string) (string, string) {
	return c[fmt.Sprintf("%s:%s", host, "oauth_token")], c["_source"]
}

func (c tinyConfig) ActiveUser(host string) (string, error) {
	return c[fmt.Sprintf("%s:%s", host, "user")], nil
}

func (c tinyConfig) TokenForUser(host, user string) (string, string, error) {
	token := c[fmt.Sprintf("%s:%s:%s", host, user, "oauth_token")]
	if token == "" {
		return "", "", fmt.Errorf("no token")
	}
	source := c[fmt.Sprintf("%s:%s:%s", host, user, "source")]
	if source == "" {
		source = c["_source"]
	}
	return token, source, nil
}

func (c tinyConfig) RepositoryUser(host, slug string) string {
	if slug == "" {
		return ""
	}
	key := fmt.Sprintf("%s:%s:%s", host, "repositories", strings.ToLower(slug))
	return c[key]
}

func Test_helperRun(t *testing.T) {
	tests := []struct {
		name       string
		opts       CredentialOptions
		input      string
		wantStdout string
		wantStderr string
		wantErr    bool
	}{
		{
			name: "host only, credentials found",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":        "monalisa",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=monalisa
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "host plus user",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":        "monalisa",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
				username=monalisa
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=monalisa
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "gist host",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                "/Users/monalisa/.config/gh/hosts.yml",
						"github.com:user":        "monalisa",
						"github.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=gist.github.com
				username=monalisa
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=gist.github.com
				username=monalisa
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "url input",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":        "monalisa",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				url=https://monalisa@example.com
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=monalisa
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "host only, no credentials found",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":          "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user": "monalisa",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
			`),
			wantErr:    true,
			wantStdout: "",
			wantStderr: "",
		},
		{
			name: "user mismatch",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":        "monalisa",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
				username=hubot
			`),
			wantErr:    true,
			wantStdout: "",
			wantStderr: "",
		},
		{
			name: "no username configured",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=x-access-token
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "token from env",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                 "GITHUB_ENTERPRISE_TOKEN",
						"example.com:oauth_token": "OTOKEN",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
				username=hubot
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=x-access-token
				password=OTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "host plus alternate user token",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                       "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":              "monalisa",
						"example.com:oauth_token":       "OTOKEN",
						"example.com:hubot:oauth_token": "HTOKEN",
						"example.com:hubot:source":      "oauth_token",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
				username=hubot
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=hubot
				password=HTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "owner derived from path",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                       "/Users/monalisa/.config/gh/hosts.yml",
						"example.com:user":              "monalisa",
						"example.com:oauth_token":       "OTOKEN",
						"example.com:hubot:oauth_token": "HTOKEN",
						"example.com:hubot:source":      "oauth_token",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=example.com
				path=/hubot/project.git
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=example.com
				username=hubot
				password=HTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "repository mapping takes precedence",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                                     "/Users/monalisa/.config/gh/hosts.yml",
						"github.com:user":                             "monalisa",
						"github.com:oauth_token":                      "DEFAULT",
						"github.com:samplebuilder:oauth_token":        "SBTOKEN",
						"github.com:samplebuilder:source":             "oauth_token",
						"github.com:examplebot:oauth_token":           "EBOT",
						"github.com:repositories:examplecorp":         "samplebuilder",
						"github.com:repositories:examplecorp/widgets": "examplebot",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=github.com
				path=/examplecorp/widgets.git
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=github.com
				username=examplebot
				password=EBOT
			`),
			wantStderr: "",
		},
		{
			name: "owner mapping fallback",
			opts: CredentialOptions{
				Operation: "get",
				Config: func() (config, error) {
					return tinyConfig{
						"_source":                "/Users/monalisa/.config/gh/hosts.yml",
						"github.com:user":        "monalisa",
						"github.com:oauth_token": "DEFAULT",
						"github.com:someuser_GithubEMUOrg:oauth_token": "PTOKEN",
						"github.com:repositories:examplecorp":          "someuser_GithubEMUOrg",
					}, nil
				},
			},
			input: heredoc.Doc(`
				protocol=https
				host=github.com
				path=/ExampleCorp/gizmo
			`),
			wantErr: false,
			wantStdout: heredoc.Doc(`
				protocol=https
				host=github.com
				username=someuser_GithubEMUOrg
				password=PTOKEN
			`),
			wantStderr: "",
		},
		{
			name: "noop store operation",
			opts: CredentialOptions{
				Operation: "store",
			},
		},
		{
			name: "noop erase operation",
			opts: CredentialOptions{
				Operation: "erase",
			},
		},
		{
			name: "unknown operation",
			opts: CredentialOptions{
				Operation: "unknown",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ios, stdin, stdout, stderr := iostreams.Test()
			fmt.Fprint(stdin, tt.input)
			opts := &tt.opts
			opts.IO = ios
			if err := helperRun(opts); (err != nil) != tt.wantErr {
				t.Fatalf("helperRun() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantStdout != stdout.String() {
				t.Errorf("stdout: got %q, wants %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != stderr.String() {
				t.Errorf("stderr: got %q, wants %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
