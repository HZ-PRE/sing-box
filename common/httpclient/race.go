package httpclient

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Only hedge requests whose application semantics permit duplicate delivery.
func requestCanRace(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions) && requestReplayable(r)
}

// Each contender owns its cancellation. In particular, returning response
// headers must not cancel the winning response's still-streaming body.
func raceRoundTrip(r *http.Request, delay time.Duration, first, second func(*http.Request) (*http.Response, error), firstFailed func()) (*http.Response, bool, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}
	contexts := [2]context.Context{}
	cancels := [2]context.CancelFunc{}
	for i := range contexts {
		contexts[i], cancels[i] = context.WithCancel(r.Context())
	}
	type result struct {
		response *http.Response
		err      error
		index    int
	}
	results := make(chan result, 2)
	started, received := 0, 0
	start := func(index int, roundTrip func(*http.Request) (*http.Response, error)) {
		started++
		go func() {
			request := r.Clone(contexts[index])
			if r.Body != nil && r.Body != http.NoBody {
				body, err := r.GetBody()
				if err != nil {
					results <- result{err: err, index: index}
					return
				}
				request.Body = body
			}
			response, err := roundTrip(request)
			results <- result{response, err, index}
		}()
	}
	drain := func() {
		if pending := started - received; pending > 0 {
			go func() {
				for range pending {
					result := <-results
					if result.response != nil && result.response.Body != nil {
						result.response.Body.Close()
					}
				}
			}()
		}
	}
	start(0, first)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var failures [2]error
	for {
		select {
		case <-r.Context().Done():
			cancels[0]()
			cancels[1]()
			drain()
			return nil, false, r.Context().Err()
		case <-timer.C:
			if started == 1 {
				start(1, second)
			}
		case result := <-results:
			received++
			if result.err == nil && result.response != nil {
				cancels[1-result.index]()
				drain()
				if result.response.Body == nil {
					cancels[result.index]()
				} else {
					result.response.Body = &managedResponseBody{body: result.response.Body, release: cancels[result.index]}
				}
				return result.response, result.index == 0, nil
			}
			cancels[result.index]()
			if result.response != nil && result.response.Body != nil {
				result.response.Body.Close()
			}
			if result.err == nil {
				result.err = errors.New("HTTP transport returned no response")
			}
			failures[result.index] = result.err
			if result.index == 0 && firstFailed != nil && r.Context().Err() == nil {
				firstFailed()
			}
			if started == 1 {
				timer.Stop()
				start(1, second)
			}
			if received == 2 {
				return nil, false, errors.Join(failures[0], failures[1])
			}
		}
	}
}
