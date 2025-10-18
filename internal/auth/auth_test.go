package auth

import (
	"strings"
	"testing"
	"net/http"
	"errors"
)

type returnValues struct{	
	auth string
	err error
}

func TestGetApiKey(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	tests := map[string]struct {
		inputKey string
		inputValue string
		want returnValues
	}{
		"correct" : {inputKey: "Authorization", inputValue: "ApiKey eyJKekus", want: returnValues{ auth: "eyJKekus", err: nil}},
		"noAuthHeader" : {inputKey: "none", inputValue: "ApiKey eyJKekus", want: returnValues{ auth: "", err: errors.New("no authorization header included")}},
		"missingDirective" : {inputKey: "Authorization", inputValue: "ApiKey", want: returnValues{ auth: "", err: errors.New("malformed authorization header")}},
		"wrongAuthType" : {inputKey: "Authorization", inputValue: "Basic etetet", want: returnValues{ auth: "", err: errors.New("malformed authorization header")}},
	}
	for name, testCase := range tests {
		header := req.Header.Clone()
		header.Add(testCase.inputKey, testCase.inputValue)
		got, apiErr := GetAPIKey(header)
		gotStruct := returnValues{
			auth: got,
			err: apiErr,
		}
		if !CompareHeaders(name, gotStruct, testCase.want, t){
			t.Fatalf("%s: expcted: %v, %v; got: %v, %v", name, testCase.want.auth, testCase.want.err, got, apiErr)
		}
	}
}
func CompareHeaders(name string, got, want returnValues, t *testing.T) bool{
	if want.err != nil{
		if got.err == nil{
			return false
		}
		if !strings.Contains(got.err.Error(), want.err.Error()){
			return false
		}
	}

	if want.err == nil && got.err != nil{
		return false
	}

	if got.auth != want.auth {
		return false
	}

	return true
}

