// Package client provides internal utilities for the twilio-go client library.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/twilio/twilio-go/client/form"
)

var alphanumericRegex *regexp.Regexp
var delimitingRegex *regexp.Regexp

func init() {
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]*$`)
	delimitingRegex = regexp.MustCompile(`\.\d+`)
}

// Credentials store user authentication credentials.
type Credentials struct {
	Username string
	Password string
}

func NewCredentials(username string, password string) *Credentials {
	return &Credentials{Username: username, Password: password}
}

type OAuth interface {
	GetAccessToken(context.Context) (string, error)
	// IsRefreshRequest reports whether a request is to the token refresh
	// endpoint. This request alone should not be sent using OAuth - it uses the
	// client secret to authenticate.
	IsRefreshRequest(method, path string) bool
}

// Client encapsulates a standard HTTP backend with authorization.
type Client struct {
	*Credentials
	HTTPClient          *http.Client
	accountSid          string
	UserAgentExtensions []string
	OAuth               OAuth
}

// default http Client should not follow redirects and return the most recent response.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Second * 10,
	}
}

func (c *Client) basicAuth() (string, string) {
	return c.Credentials.Username, c.Credentials.Password
}

// SetTimeout sets the Timeout for HTTP requests.
func (c *Client) SetTimeout(timeout time.Duration) {
	if c.HTTPClient == nil {
		c.HTTPClient = defaultHTTPClient()
	}
	c.HTTPClient.Timeout = timeout
}

func extractContentTypeHeader(headers map[string]interface{}) (cType string) {
	headerType, ok := headers["Content-Type"]
	if !ok {
		return urlEncodedContentType
	}
	return headerType.(string)
}

const (
	urlEncodedContentType = "application/x-www-form-urlencoded"
	jsonContentType       = "application/json"
	keepZeros             = true
	delimiter             = '.'
	escapee               = '\\'
)

func (c *Client) doWithErr(req *http.Request) (*http.Response, error) {
	client := c.HTTPClient

	if client == nil {
		client = defaultHTTPClient()
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Note that 3XX response codes are allowed for fetches
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		err = &TwilioRestError{}
		if decodeErr := json.NewDecoder(res.Body).Decode(err); decodeErr != nil {
			err = errors.Wrap(decodeErr, "error decoding the response for an HTTP error code: "+strconv.Itoa(res.StatusCode))
			return nil, err
		}

		return nil, err
	}
	return res, nil
}

// throws error if username and password contains special characters
func (c *Client) validateCredentials() error {
	username, password := c.basicAuth()
	if !alphanumericRegex.MatchString(username) {
		return &TwilioRestError{
			Status:   400,
			Code:     21222,
			Message:  "Invalid Username. Illegal chars",
			MoreInfo: "https://www.twilio.com/docs/errors/21222"}
	}
	if !alphanumericRegex.MatchString(password) {
		return &TwilioRestError{
			Status:   400,
			Code:     21224,
			Message:  "Invalid Password. Illegal chars",
			MoreInfo: "https://www.twilio.com/docs/errors/21224"}
	}
	return nil
}

var baseUserAgent string
var userAgentOnce sync.Once

// SendRequest verifies, constructs, and authorizes an HTTP request.
func (c *Client) SendRequest(method string, rawURL string, data url.Values,
	headers map[string]interface{}, body ...byte) (*http.Response, error) {
	ctx := context.TODO()

	contentType := extractContentTypeHeader(headers)

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	valueReader := &strings.Reader{}
	var req *http.Request

	// For an HTTP GET request, there are no body parameters. All other
	// parameters (such as query and path) are appended directly to the URL.
	// When the Content-Type is JSON, we might still send a JSON body. In that
	// scenario, the 'data' variable holds every parameter except those in the
	// body, just like in a GET request, where all parameters are added to
	// the URL.
	if method == http.MethodGet || method == http.MethodDelete || contentType == jsonContentType {
		if data != nil {
			v, _ := form.EncodeToStringWith(data, delimiter, escapee, keepZeros)
			s := delimitingRegex.ReplaceAllString(v, "")

			u.RawQuery = s
		}
	}

	// data is already processed and information will be added to u(the url) in the
	// previous step. Now the body will contain only the json payload
	if contentType == jsonContentType {
		req, err = http.NewRequestWithContext(ctx, method, u.String(), bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
	} else {
		// Here the HTTP POST methods which do not have json content type are processed
		// All the values will be added in data and encoded (all body, query, path parameters)
		if method == http.MethodPost || method == http.MethodPut {
			valueReader = strings.NewReader(data.Encode())
		}
		req, err = http.NewRequestWithContext(ctx, method, u.String(), valueReader)
		if err != nil {
			return nil, err
		}

	}

	credErr := c.validateCredentials()
	if credErr != nil {
		return nil, credErr
	}
	if c.OAuth == nil && c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.basicAuth())
	}

	// E.g. "User-Agent": "twilio-go/1.0.0 (darwin amd64) go/go1.17.8"
	userAgentOnce.Do(func() {
		goVersion := runtime.Version()
		if strings.HasPrefix(goVersion, "devel ") {
			// everything after "devel " is the interesting part
			parts := strings.SplitN(goVersion, " ", 3)
			if len(parts) == 3 {
				goVersion = parts[1]
			}
		}
		baseUserAgent = fmt.Sprintf("twilio-go/%s (%s %s) go/%s", LibraryVersion, runtime.GOOS, runtime.GOARCH, goVersion)
	})
	userAgent := baseUserAgent

	if len(c.UserAgentExtensions) > 0 {
		userAgent += " " + strings.Join(c.UserAgentExtensions, " ")
	}
	req.Header.Add("User-Agent", userAgent)

	if c.OAuth != nil && !c.OAuth.IsRefreshRequest(method, u.Path) {
		fmt.Println("call get access token")
		token, _ := c.OAuth.GetAccessToken(ctx)
		fmt.Println("token", token)
		if token != "" {
			req.Header.Add("Authorization", "Bearer "+token)
		}
	} else if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.basicAuth())
	}

	for k, v := range headers {
		req.Header.Add(k, fmt.Sprint(v))
	}
	return c.doWithErr(req)
}

// SetAccountSid sets the Client's accountSid field
func (c *Client) SetAccountSid(sid string) {
	c.accountSid = sid
}

// AccountSid returns the Account SID.
func (c *Client) AccountSid() string {
	return c.accountSid
}
