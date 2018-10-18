package lastpassaws

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Login will submit the credentials to LastPass to login and create the
// session for future use
func Login(session *http.Client, username, password, otp string) error {

	iterations := iterations(session, username)

	lpLoginPage := lastPassServer + "/login.php"

	params := url.Values{
		"method":     {"web"},
		"xml":        {"1"},
		"username":   {username},
		"hash":       {string(makeHash(username, password, iterations))},
		"iterations": {fmt.Sprint(iterations)},
	}

	if otp != "" {
		params.Add("otp", otp)
	}

	resp, err := session.PostForm(lpLoginPage, params)
	if err != nil {
		fmt.Print("Err", err)
		return err
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	return err
}
