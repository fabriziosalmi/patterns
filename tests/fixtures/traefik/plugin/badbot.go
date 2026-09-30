// A stand-in for the `badbot` middleware plugin the generated Traefik output is
// written for, so that the output can be run through a real Traefik.
//
// The output is `[http.middlewares.NAME.plugin.badbot]` with `userAgent = [...]`,
// a list of regular expressions for the User-Agent header. This is the smallest
// thing that honours that: compile each with Go's regexp (RE2, the engine a Go
// plugin has), refuse with 403 when any matches the header, and fail to start
// when one does not compile. It says nothing about any published plugin: what
// this checks is that Traefik accepts the configuration and what the expressions
// do in RE2.
package badbot

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
)

// Config is the plugin configuration: the expressions to refuse.
type Config struct {
	UserAgent []string `json:"userAgent,omitempty"`
}

// CreateConfig creates the default configuration.
func CreateConfig() *Config {
	return &Config{}
}

// BadBot refuses a request whose User-Agent matches an expression.
type BadBot struct {
	next     http.Handler
	patterns []*regexp.Regexp
}

// New compiles the expressions. One that does not compile stops the middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	patterns := make([]*regexp.Regexp, 0, len(config.UserAgent))
	for _, expression := range config.UserAgent {
		compiled, err := regexp.Compile(expression)
		if err != nil {
			return nil, fmt.Errorf("badbot %s: userAgent %q: %w", name, expression, err)
		}
		patterns = append(patterns, compiled)
	}
	return &BadBot{next: next, patterns: patterns}, nil
}

func (b *BadBot) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	agent := req.UserAgent()
	for _, pattern := range b.patterns {
		if pattern.MatchString(agent) {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
	}
	b.next.ServeHTTP(rw, req)
}
