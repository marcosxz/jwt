package jwt

import (
	"testing"
	"time"
)

func TestGetJWT(t *testing.T) {

	secret := "dssadasdasd"

	token, err := New(
		WithIss("1"),
		WithSub("1"),
		WithAud("1"),
		WithJti("1"),
		WithExp(60),
		WithNbf(time.Now().Unix()),
		WithSecret(secret),
		WithInternal("1", "1"),
		WithInternal("2", "2"),
		WithInternal("3", "3"),
		WithExternal("4", "4"),
		WithExternal("5", "5"),
		WithExternal("6", "6"),
		WithCheckFunc(func(token, secret string) (token2 *Token, e error) {
			return defaultCheck(token, secret)
		}),
	)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("%+v, %+v, %+v, %s, %s \n", token.Header, token.Payload, token.Signature, token.String(), token.secret)

	token, err = Check(token.String(), secret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("%+v, %+v, %+v, %s, %s \n", token.Header, token.Payload, token.Signature, token.String(), token.secret)
}
