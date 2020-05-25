package lastpassaws

import (
	"fmt"
	"net/http"
	"net/url"
)

// GetLastpassIdentitySession returns true if identity session is created
func GetLastpassIdentitySession(session *http.Client) error {
	resp, err := session.Get(LastPassServer + "/saml/launch/nopassword?RelayState=/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Wrong status code from /saml/launch/nopassword: %s", resp.Status)
	}

	action, fields := extractForm(resp.Body)
	if action == "" {
		// Error with account
		return fmt.Errorf("Not logged in")
	}

	samlResponse := fields["SAMLResponse"]

	params := url.Values{
		"SAMLResponse": {samlResponse},
	}

	resp, err = session.PostForm(action, params)
	if err != nil {
		return err
	}

	return nil

}
