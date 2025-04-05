package twilio

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_WithParams(t *testing.T) {
	client := NewRestClientWithParams(ClientParams{
		Username:   "parentSid",
		Password:   "authToken",
		AccountSid: "subAccountSid",
	})

	assert.Equal(t, client.RequestHandler.Client.AccountSid(), "subAccountSid")
}

func TestClient_WithNoAccountSid(t *testing.T) {
	client := NewRestClientWithParams(ClientParams{
		Username: "parentSid",
		Password: "authToken",
	})
	assert.Equal(t, client.RequestHandler.Client.AccountSid(), "parentSid")
}

func TestClientCredentialProvider(t *testing.T) {
	creds := ClientCredentialProvider{
		GrantType:    "client_credentials",
		ClientId:     "mock_client_id",
		ClientSecret: "mock_client_secret",
	}
	client := NewRestClientWithParams(ClientParams{
		Username:                 "parentSid",
		Password:                 "authToken",
		ClientCredentialProvider: &creds,
	},
	)
	count := 0
	var firstURL, secondURL string
	var grant string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if count == 1 {
			firstURL = r.URL.String()
			grant = r.FormValue("grant_type")
		} else {
			secondURL = r.URL.String()
		}
	}))
	defer server.Close()

	client.IamV1.SetBaseURL(server.URL)

	resp, err := client.Client.SendRequest("GET", server.URL+"/anyurl", nil, nil)
	assert.Equal(t, count, 2, "Expected 2 requests to be made, first an oauth request, then the actual request")
	assert.Equal(t, firstURL, "/v1/token")
	assert.Equal(t, secondURL, "/anyurl")
	assert.Equal(t, grant, "client_credentials")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
