// Package bing logic
package bing

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {

		for i := 1; i <= 201; i += 10 {

			baseURL := fmt.Sprintf("https://www.bing.com/search?q=domain%%3a%s+-site%%3awww.%s&pq=domain%%3a%s+-site%%3awww.%s&first=%d&FORM=PERE",
				domain, domain, domain, domain, i)

			resp, err := session.SimpleGet(ctx, baseURL)
			isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
			if err != nil && !isnotfound {
				results <- subscraping.Result{Source: "bing", Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: "bing", Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			src := string(body)
			for _, match := range session.Extractor.FindAllString(src, -1) {
				if !strings.Contains(match, "3awww.") {
					results <- subscraping.Result{Source: "bing", Type: subscraping.Subdomain, Value: match}
				}
			}

			time.Sleep(time.Duration((5 + rand.Intn(SleepRandIntn))) * time.Second)
		}

		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bing"
}