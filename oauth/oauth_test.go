package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
)

// TestMain is main entrypoint for each of package
// M.run mean run all test cases in this test file
func TestMain(m *testing.M) {
	fmt.Println("about to start oauth test")
	// indicate below test cases all use mock server api instead of real api call
	rest.StartMockupServer()
	os.Exit(m.Run())
}

func TestOauthConstant(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}
func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerIdNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetCallerId(nil))
}
func TestGetCallerIdWrongFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-Id", "wrong format")
	assert.EqualValues(t, 0, GetCallerId(&request))
}
func TestGetCallerIdNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-Id", "1")
	assert.EqualValues(t, 1, GetCallerId(&request))
}

func TestGetAccessTokenNoneValidResponse(t *testing.T) {
	// every time we start new rest client call the first thing we need to do is flush mockup
	// make sure we work on fresh enviroment, we don't left any past mock in rest client
	rest.FlushMockups()
	// set up your mock server rules
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/1",
		ReqBody:      ``,
		RespHTTPCode: -1,   //we put invalid http response code
		RespBody:     `{}`, //empty return
	})

	accessToken, err := getAccessToken("1")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status)
	assert.EqualValues(t, "invalid restclient response when trying to get access token", err.Message)
	assert.EqualValues(t, "internal_server_error", err.Error)
	assert.EqualValues(t, "invalid response", err.Causes[0])
}

func TestGetAccessTokenReceiveWrongFormatRestErrorResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/2",
		ReqBody:      ``,
		RespHTTPCode: http.StatusBadRequest,
		// rest_error Status should be number
		RespBody: `{
			"Message": "Bad Request",
			"Status": "400",
			"Error": "API params wrong"
		}`,
	})
	accessToken, err := getAccessToken("2")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status)
	assert.EqualValues(t, "invalid error interface when trying to get access token", err.Message)
	assert.EqualValues(t, "internal_server_error", err.Error)
	assert.EqualValues(t, "contract error", err.Causes[0])
}

func TestGetAccessTokenReceiveCorrectRestErrorResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/3",
		ReqBody:      ``,
		RespHTTPCode: http.StatusBadRequest,
		// rest_error Status should be number
		RespBody: `{
			"Message": "Bad Request",
			"Status": 400,
			"Error": "API params wrong"
		}`,
	})
	accessToken, err := getAccessToken("3")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusBadRequest, err.Status)
	assert.EqualValues(t, "Bad Request", err.Message)
	assert.EqualValues(t, "API params wrong", err.Error)
}

func TestGetAccessTokenReceiveWrongFormatOfAccessTokenResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/4",
		ReqBody:      ``,
		RespHTTPCode: http.StatusOK,
		// Id should be string type
		RespBody: `{"id": "1","user_id": "10","client_id": "5"}`,
	})
	accessToken, err := getAccessToken("4")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status)
	assert.EqualValues(t, "error when trying to unmarshal access token response", err.Message)
	assert.EqualValues(t, "internal_server_error", err.Error)
	assert.EqualValues(t, "contract error", err.Causes[0])
}

func TestGetAccessTokenSuccess(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/5",
		ReqBody:      ``,
		RespHTTPCode: http.StatusOK,
		RespBody:     `{"id": "1","user_id": 10,"client_id": 5}`,
	})
	accessToken, err := getAccessToken("5")
	assert.NotNil(t, accessToken)
	assert.Nil(t, err)
	assert.EqualValues(t, accessToken.Id, "1")
	assert.EqualValues(t, accessToken.UserId, 10)
	assert.EqualValues(t, accessToken.ClientId, 5)
}
