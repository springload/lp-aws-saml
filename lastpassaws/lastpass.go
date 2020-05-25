package lastpassaws

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Login will submit the credentials to LastPass to login and create the
// session for future use
func Login(session *http.Client, username, password, otp string) error {

	iterations := iterations(session, username)

	lpLoginPage := LastPassServer + "/login.php"

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
	// check the status code, because lastpass returns 500x quite often
	if resp.StatusCode != 200 {
		return fmt.Errorf("Wrong status: %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	body := string(bodyBytes)
	if strings.Contains(body, "verifydevice") {
		return fmt.Errorf("LastPass doesn't recognize this device or you're at a new location. Please check your email to grant access to your new device or location")
	}
	return err
}
