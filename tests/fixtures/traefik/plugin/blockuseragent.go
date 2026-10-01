// Package traefik_plugin_blockuseragent a plugin to block User-Agent.
package traefik_plugin_blockuseragent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// Config holds the plugin configuration.
type Config struct {
	RegexAllow []string `json:"regexAllow,omitempty"`
	Regex      []string `json:"regex,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{RegexAllow: make([]string, 0), Regex: make([]string, 0)}
}

// BlockUserAgent struct.
type BlockUserAgent struct {
	name         string
	next         http.Handler
	regexpsAllow []*regexp.Regexp
	regexpsDeny  []*regexp.Regexp
}

// BlockUserAgentMessage struct.
type BlockUserAgentMessage struct {
	Regex      int    `json:"regex"`
	UserAgent  string `json:"user-agent"`
	RemoteAddr string `json:"ip"`
	Host       string `json:"host"`
	RequestURI string `json:"uri"`
}

// New creates and returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	regexpsAllow := make([]*regexp.Regexp, len(config.RegexAllow))
	regexpsDeny := make([]*regexp.Regexp, len(config.Regex))

	for index, regex := range config.RegexAllow {
		re, err := regexp.Compile(regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regexAllow %q: %w", regex, err)
		}

		regexpsAllow[index] = re
	}

	for index, regex := range config.Regex {
		re, err := regexp.Compile(regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex %q: %w", regex, err)
		}

		regexpsDeny[index] = re
	}

	return &BlockUserAgent{
		name:         name,
		next:         next,
		regexpsAllow: regexpsAllow,
		regexpsDeny:  regexpsDeny,
	}, nil
}

func (b *BlockUserAgent) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req != nil {
		userAgent := req.UserAgent()

		for _, re := range b.regexpsAllow {
			if re.MatchString(userAgent) {
				b.next.ServeHTTP(res, req)

				return
			}
		}

		for index, re := range b.regexpsDeny {
			if re.MatchString(userAgent) {
				message := &BlockUserAgentMessage{
					Regex:      index,
					UserAgent:  userAgent,
					RemoteAddr: req.RemoteAddr,
					Host:       req.Host,
					RequestURI: req.RequestURI,
				}
				jsonMessage, err := json.Marshal(message)

				if err == nil {
					log.Printf("%s: %s", b.name, jsonMessage)
				}

				res.WriteHeader(http.StatusForbidden)

				return
			}
		}
	}

	b.next.ServeHTTP(res, req)
}
