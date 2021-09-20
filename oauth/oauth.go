package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/shawnzxx/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

const (
	AuthServiceHost = "AUTH_SERVICE_HOST"
)

var (
	oauthRestClient = GetNewRestClient()
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func GetNewRestClient() rest.RequestBuilder {
	host := os.Getenv(AuthServiceHost)
	if len(host) == 0 {
		host = "http://localhost:8080"
	}
	return rest.RequestBuilder{
		BaseURL: host,
		Timeout: 200 * time.Millisecond,
	}
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	//clean what ever passed in header
	cleanRequest(request)

	// Any api request with access_token appened behind, for example get user request
	// localhost:8080/users/1?access_token=123abc
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	//if get access token from oauth service, fill in actual request header
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *rest_errors.RestErr) {
	//path route refer to oauth api service
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	// invalid response from API call
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to get access token", errors.New("invalid response"))
	}

	// means error happened
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		// jsonString := string(response.Bytes())
		// fmt.Printf("api response: %s\n", jsonString)

		// since we use same rest error struct for both auth and user service
		// if can not unmarshal response means someone changed the struct
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", errors.New("contract error"))
		}
		// error struct no change return real response error
		return nil, &restErr
	}

	var at accessToken
	var bodyBytes = response.Bytes()
	bodyString := string(bodyBytes)
	fmt.Println(bodyString)
	err := json.Unmarshal(bodyBytes, &at)
	if err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("contract error"))
	}

	return &at, nil
}
