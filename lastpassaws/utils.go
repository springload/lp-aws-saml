package lastpassaws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// LastPassServer points to the Lastpass Server
const LastPassServer = "https://lastpass.com"

func iterations(session *http.Client, username string) int {
	iterations := 5000

	lpIterationPage := LastPassServer + "/iterations.php"

	params := url.Values{
		"email": {username},
	}
	resp, err := session.PostForm(lpIterationPage, params)
	if err == nil {
		defer resp.Body.Close()
		contents, _ := ioutil.ReadAll(resp.Body)
		iterations, _ = strconv.Atoi(string(contents))
	}

	return iterations
}

func makeKey(username, password string, iterationCount int) []byte {
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), iterationCount, 32, sha256.New)
}

func makeHash(username, password string, iterationCount int) []byte {
	key := makeKey(username, password, iterationCount)
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(string(encodeHex(key)) + password))
		return encodeHex(b[:])
	}
	return encodeHex(pbkdf2.Key([]byte(key), []byte(password), 1, 32, sha256.New))
}

func encodeHex(b []byte) []byte {
	d := make([]byte, len(b)*2)
	n := hex.Encode(d, b)
	return d[:n]
}

func decodeHex(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := hex.Decode(d, b)
	return d[:n]
}

func decodeBase64(b string) string {
	decoded, _ := base64.StdEncoding.DecodeString(b)
	return string(decoded)
}

func encodeBase64(b string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(b))
	return encoded
}

// HomeDir returns the user's home directory
func HomeDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"))
	}
	return os.Getenv("HOME")
}
