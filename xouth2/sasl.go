package xouth2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Common SASL errors.
var (
	ErrUnexpectedClientResponse  = errors.New("sasl: unexpected client response")
	ErrUnexpectedServerChallenge = errors.New("sasl: unexpected server challenge")
)

// Client interface to perform challenge-response authentication.
type Client interface {
	// Begins SASL authentication with the server. It returns the
	// authentication mechanism name and "initial response" data (if required by
	// the selected mechanism). A non-nil error causes the client to abort the
	// authentication attempt.
	//
	// A nil ir value is different from a zero-length value. The nil value
	// indicates that the selected mechanism does not use an initial response,
	// while a zero-length value indicates an empty initial response, which must
	// be sent to the server.
	Start() (mech string, ir []byte, err error)

	// Continues challenge-response authentication. A non-nil error causes
	// the client to abort the authentication attempt.
	Next(challenge []byte) (response []byte, err error)
}

// Server interface to perform challenge-response authentication.
type Server interface {
	// Begins or continues challenge-response authentication. If the client
	// supplies an initial response, response is non-nil.
	//
	// If the authentication is finished, done is set to true. If the
	// authentication has failed, an error is returned.
	Next(response []byte) (challenge []byte, done bool, err error)
}

// The XOAUTH2 mechanism name.
const XOAUTH2 = "XOAUTH2"

type XOAUTH2Error struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type XOAUTH2Options struct {
	Username string
	Token    string
	Host     string
	Port     int
}

// Implements error
func (err *XOAUTH2Error) Error() string {
	return fmt.Sprintf("XOAUTH2 authentication error (%v): %v", err.Status, err.Message)
}

type xoauth2Client struct {
	XOAUTH2Options
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	var authzid string
	if a.Username != "" {
		authzid = "a=" + a.Username
	}
	str := "n," + authzid + ","

	if a.Host != "" {
		str += "\x01host=" + a.Host
	}

	if a.Port != 0 {
		str += "\x01port=" + strconv.Itoa(a.Port)
	}
	str += "\x01auth=Bearer " + a.Token + "\x01\x01"
	ir = []byte(str)
	return XOAUTH2, ir, nil
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	xoauth2Err := &XOAUTH2Error{}
	if err := json.Unmarshal(challenge, xoauth2Err); err != nil {
		return nil, err
	} else {
		return nil, xoauth2Err
	}
}

// An implementation of the XOAUTH2 authentication mechanism.
func NewXOAUTH2Client(opt *XOAUTH2Options) Client {
	return &xoauth2Client{*opt}
}

type XOAUTH2Authenticator func(opts XOAUTH2Options) *XOAUTH2Error

type xoauth2Server struct {
	done         bool
	failErr      error
	authenticate XOAUTH2Authenticator
}

func (a *xoauth2Server) fail(descr string) ([]byte, bool, error) {
	blob, err := json.Marshal(XOAUTH2Error{
		Status:  "invalid_request",
		Message: descr,
	})
	if err != nil {
		panic(err) // wtf
	}
	a.failErr = errors.New("sasl: client error: " + descr)
	return blob, false, nil
}

func (a *xoauth2Server) Next(response []byte) (challenge []byte, done bool, err error) {
	if a.failErr != nil {
		if len(response) != 1 && response[0] != 0x01 {
			return nil, true, errors.New("sasl: invalid response")
		}
		return nil, true, a.failErr
	}

	if a.done {
		err = ErrUnexpectedClientResponse
		return
	}

	if response == nil {
		return []byte{}, false, nil
	}

	a.done = true

	parts := bytes.SplitN(response, []byte{','}, 3)
	if len(parts) != 3 {
		return a.fail("Invalid response")
	}
	flag := parts[0]
	authzid := parts[1]
	if !bytes.Equal(flag, []byte{'n'}) {
		return a.fail("Invalid response, missing 'n' in gs2-cb-flag")
	}
	opts := XOAUTH2Options{}
	if len(authzid) > 0 {
		if !bytes.HasPrefix(authzid, []byte("a=")) {
			return a.fail("Invalid response, missing 'a=' in gs2-authzid")
		}
		opts.Username = string(bytes.TrimPrefix(authzid, []byte("a=")))
	}

	params := bytes.Split(parts[2], []byte{0x01})
	for _, p := range params {
		if len(p) == 0 {
			continue
		}

		pParts := bytes.SplitN(p, []byte{'='}, 2)
		if len(pParts) != 2 {
			return a.fail("Invalid response, missing '='")
		}

		switch string(pParts[0]) {
		case "host":
			opts.Host = string(pParts[1])
		case "port":
			port, err := strconv.ParseUint(string(pParts[1]), 10, 16)
			if err != nil {
				return a.fail("Invalid response, malformed 'port' value")
			}
			opts.Port = int(port)
		case "auth":
			const prefix = "bearer "
			strValue := string(pParts[1])
			if !strings.HasPrefix(strings.ToLower(strValue), prefix) {
				return a.fail("Unsupported token type")
			}
			opts.Token = strValue[len(prefix):]
		default:
			return a.fail("Invalid response, unknown parameter: " + string(pParts[0]))
		}
	}

	authzErr := a.authenticate(opts)
	if authzErr != nil {
		blob, err := json.Marshal(authzErr)
		if err != nil {
			panic(err) // wtf
		}
		a.failErr = authzErr
		return blob, false, nil
	}

	return nil, true, nil
}

func NewXOAUTH2Server(auth XOAUTH2Authenticator) Server {
	return &xoauth2Server{authenticate: auth}
}
