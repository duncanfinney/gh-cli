package login

import (
	"bufio"
	"fmt"
	"net/url"
	"strings"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/spf13/cobra"
)

const tokenUser = "x-access-token"

type config interface {
	ActiveToken(string) (string, string)
	ActiveUser(string) (string, error)
	TokenForUser(string, string) (string, string, error)
	RepositoryUser(string, string) string
}

type CredentialOptions struct {
	IO     *iostreams.IOStreams
	Config func() (config, error)

	Operation string
}

func NewCmdCredential(f *cmdutil.Factory, runF func(*CredentialOptions) error) *cobra.Command {
	opts := &CredentialOptions{
		IO: f.IOStreams,
		Config: func() (config, error) {
			cfg, err := f.Config()
			if err != nil {
				return nil, err
			}
			return cfg.Authentication(), nil
		},
	}

	cmd := &cobra.Command{
		Use:    "git-credential",
		Args:   cobra.ExactArgs(1),
		Short:  "Implements git credential helper protocol",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Operation = args[0]

			if runF != nil {
				return runF(opts)
			}
			return helperRun(opts)
		},
	}

	return cmd
}

func helperRun(opts *CredentialOptions) error {
	if opts.Operation == "store" {
		// We pretend to implement the "store" operation, but do nothing since we already have a cached token.
		return nil
	}

	if opts.Operation == "erase" {
		// We pretend to implement the "erase" operation, but do nothing since we don't want git to cause user to be logged out.
		return nil
	}

	if opts.Operation != "get" {
		return fmt.Errorf("gh auth git-credential: %q operation not supported", opts.Operation)
	}

	wants := map[string]string{}

	s := bufio.NewScanner(opts.IO.In)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if key == "url" {
			u, err := url.Parse(value)
			if err != nil {
				return err
			}
			wants["protocol"] = u.Scheme
			wants["host"] = u.Host
			wants["path"] = u.Path
			wants["username"] = u.User.Username()
			wants["password"], _ = u.User.Password()
		} else {
			wants[key] = value
		}
	}
	if err := s.Err(); err != nil {
		return err
	}

	if wants["protocol"] != "https" {
		return cmdutil.SilentError
	}

	cfg, err := opts.Config()
	if err != nil {
		return err
	}

	lookupHost := wants["host"]
	hostOptions := []string{lookupHost}
	if strings.HasPrefix(lookupHost, "gist.") {
		hostOptions = append(hostOptions, strings.TrimPrefix(lookupHost, "gist."))
	}

	candidateUsers := collectCandidateUsers(cfg, wants, hostOptions)

	var (
		gotToken     string
		source       string
		gotUser      string
		resolvedHost string
	)

userLookup:
	for _, user := range candidateUsers {
		for _, hostOption := range hostOptions {
			token, tokenSource, err := cfg.TokenForUser(hostOption, user)
			if err == nil && token != "" {
				gotToken = token
				source = tokenSource
				gotUser = user
				resolvedHost = hostOption
				break userLookup
			}
		}
	}

	if gotToken == "" {
		for _, hostOption := range hostOptions {
			token, tokenSource := cfg.ActiveToken(hostOption)
			if token != "" {
				gotToken = token
				source = tokenSource
				resolvedHost = hostOption
				break
			}
		}
	}

	if gotToken == "" {
		return cmdutil.SilentError
	}

	if strings.HasSuffix(source, "_TOKEN") {
		gotUser = tokenUser
	} else if gotUser == "" {
		gotUser, _ = cfg.ActiveUser(resolvedHost)
		if gotUser == "" {
			gotUser = tokenUser
		}
	}

	if wants["username"] != "" && gotUser != tokenUser && !strings.EqualFold(wants["username"], gotUser) {
		return cmdutil.SilentError
	}

	fmt.Fprint(opts.IO.Out, "protocol=https\n")
	fmt.Fprintf(opts.IO.Out, "host=%s\n", wants["host"])
	fmt.Fprintf(opts.IO.Out, "username=%s\n", gotUser)
	fmt.Fprintf(opts.IO.Out, "password=%s\n", gotToken)

	return nil
}

func collectCandidateUsers(cfg config, wants map[string]string, hostOptions []string) []string {
	seen := map[string]struct{}{}
	add := func(user string, out *[]string) {
		user = strings.TrimSpace(user)
		if user == "" {
			return
		}
		if strings.EqualFold(user, tokenUser) {
			return
		}
		key := strings.ToLower(user)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*out = append(*out, user)
	}

	candidates := []string{}
	add(wants["username"], &candidates)
	owner, repo := ownerRepoFromPath(wants["path"])
	if owner != "" {
		if repo != "" {
			slug := owner + "/" + repo
			for _, host := range hostOptions {
				add(cfg.RepositoryUser(host, slug), &candidates)
			}
		}
		for _, host := range hostOptions {
			add(cfg.RepositoryUser(host, owner), &candidates)
		}
		add(owner, &candidates)
	}
	return candidates
}

func ownerRepoFromPath(path string) (string, string) {
	if path == "" {
		return "", ""
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return "", ""
	}
	parts := strings.SplitN(path, "/", 3)
	owner := parts[0]
	owner = strings.TrimSuffix(owner, ".git")
	var repo string
	if len(parts) > 1 {
		repo = parts[1]
	}
	if repo == "" {
		return owner, ""
	}
	repo = strings.TrimSuffix(repo, ".git")
	return owner, repo
}
