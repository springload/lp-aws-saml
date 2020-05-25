package lastpassaws

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/antchfx/xmlquery"
	"golang.org/x/net/html"
)

// SamlToken uses a LastPass login session to get a SAML token for assuming roles
func SamlToken(session *http.Client, samlURL string) (string, error) {
	resp, err := session.Get(samlURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Wrong status code from /saml/launch/cfg: %s", resp.Status)
	}

	action, fields := extractForm(resp.Body)

	if action == "" {
		// Error with account
		return "", nil
	}

	return fields["SAMLResponse"], nil
}

// SamlRoles returns a list of roles a user can assume
func SamlRoles(assertion string) [][]string {
	decoded := decodeBase64(assertion)
	path := ".//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml:AttributeValue"
	doc, _ := xmlquery.Parse(strings.NewReader(decoded))

	list := xmlquery.Find(doc, path)

	roles := make([][]string, len(list))
	for i, role := range list {
		roles[i] = strings.Split(role.InnerText(), ",")
	}

	return roles
}

// PromptForRole asks the user to choose a role if there are multiple
func PromptForRole(roles [][]string) []string {
	if len(roles) == 1 {
		return roles[0]
	}

	log.Println("Select a Role:")
	for i, role := range roles {
		fmt.Println("  " + fmt.Sprint(i+1) + ") " + role[0])
	}
	choice := 0
	for choice < 1 || choice > len(roles)+1 {
		fmt.Print("Choice: ")
		_, _ = fmt.Scan(&choice)
	}
	return roles[choice-1]
}

func extractForm(data io.ReadCloser) (string, map[string]string) {
	fields := make(map[string]string)
	action := ""

	z := html.NewTokenizer(data)
	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			// fmt.Println("End")
			return action, fields
		case tt == html.StartTagToken:
			t := z.Token()
			switch {
			case t.Data == "h2":
				// fmt.Println("Error getting saml")
				return "", nil
			case t.Data == "form":
				for _, a := range t.Attr {
					if a.Key == "action" {
						action = a.Val
						break
					}
				}
			}
		case tt == html.SelfClosingTagToken:
			t := z.Token()
			switch {
			case t.Data == "input":
				name := ""
				value := ""
				for _, a := range t.Attr {
					if a.Key == "value" {
						value = a.Val
					} else if a.Key == "name" {
						name = a.Val
					}
				}
				if name != "" && value != "" {
					fields[name] = value
				}
			}
		}
	}
}
