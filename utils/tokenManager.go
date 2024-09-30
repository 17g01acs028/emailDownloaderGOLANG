package utils

import (
	"encoding/json"
	"github.com/valyala/fasthttp"
	"net/url"
	"sync"
	"time"
)

var TokenManagerG *TokenManager

type TokenManager struct {
	token           string
	expiresIn       time.Time
	refreshInterval time.Duration
	mu              sync.Mutex
	failedLogins    int
	credentials     Credentials
}

type Credentials struct {
	ClientID     string
	ClientSecret string
	Scope        string
	AuthTokenURL string
	GrantType    string
}

func NewTokenManager(credentials Credentials) (*TokenManager, error) {
	tm := &TokenManager{
		refreshInterval: 30 * time.Minute,
		credentials:     credentials,
	}

	// Fetch the initial token
	if err := tm.refreshToken(); err != nil {
		return nil, err
	}

	// Start the auto-refresh goroutine
	go func() {
		err := tm.autoRefresh()
		if err != nil {
			return
		}
	}()

	return tm, nil
}

func (tm *TokenManager) autoRefresh() error {
	for {
		time.Sleep(tm.refreshInterval)
		err := tm.refreshToken()
		if err != nil {
			return err
		}
	}
}

func (tm *TokenManager) refreshToken() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Logic to fetch new token from the server
	newToken, err := fetchNewToken(tm.credentials)
	if err != nil {
		return err
	}

	// Update the token and expiration time
	tm.token = newToken
	tm.expiresIn = time.Now().Add(1 * time.Hour)
	return nil
}

func (tm *TokenManager) GetToken() (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for {
		if tm.token == "" {
			err := tm.refreshToken()
			if err != nil {
				return "", err
			}
			continue
		}
		break
	}

	// Check if token is expired
	if time.Now().After(tm.expiresIn) {
		err := tm.refreshToken()
		if err != nil {
			return "", err
		}
	}
	return tm.token, nil
}

func (tm *TokenManager) HandleLoginFailure() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.failedLogins++
	if tm.failedLogins >= 2 {
		err := tm.refreshToken()
		if err != nil {
			return err
		}
		tm.failedLogins = 0
	}
	return nil
}

func fetchNewToken(credentials Credentials) (string, error) {
	data := url.Values{}
	data.Set("grant_type", credentials.GrantType)
	data.Set("client_id", credentials.ClientID)
	data.Set("client_secret", credentials.ClientSecret)
	data.Set("scope", credentials.Scope)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURI(credentials.AuthTokenURL)
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(data.Encode())

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{}
	if err := client.Do(req, resp); err != nil {
		return "", err
	}

	body := resp.Body()

	type TokenResponse struct {
		AccessToken string `json:"access_token"`
	}

	var tokenResponse TokenResponse
	err := json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}
