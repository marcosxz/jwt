package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/marcosxzhang/kit"
	"strconv"
	"strings"
	"time"
)

const (
	typ = "JWT"
	alg = "HMAC SHA256"
	iss = "default"
	sub = "default"
	aud = "default"
	exp = 7200
)

var (
	InvalidToken        = errors.New("jwt token invalid")
	VerifyFailed        = errors.New("jwt token verify failed")
	InvalidNbf          = errors.New("jwt token nbf invalid")
	InvalidExp          = errors.New("jwt token exp invalid")
	InvalidIat          = errors.New("jwt token iat invalid")
	TokenNotReachedTime = errors.New("jwt token authorization has not reached the time of entry into force")
	TokenHasExpired     = errors.New("jwt token has expired")
)

var check CheckFunc = defaultCheck

type CheckFunc func(token, secret string) (*Token, error)

// Token
type Token struct {
	Header
	Payload
	Signature
	token  string
	secret string
}

func (t *Token) String() string {
	return t.token
}

func New(opts ...Option) (*Token, error) {

	// init
	token := initTokenForOptions(opts...)

	// header
	var header string
	if bs, err := kit.JsonEncoding(token.Header); err != nil {
		return nil, err
	} else {
		header = base64.StdEncoding.EncodeToString(bs)
	}

	// payload
	var payload string
	if bs, err := kit.JsonEncoding(token.Payload); err != nil {
		return nil, err
	} else {
		payload = base64.StdEncoding.EncodeToString(bs)
	}

	// join header and payload for '.', then do secret, get the jwt signature
	hps := fmt.Sprintf("%s.%s", header, payload)
	hc := hmac.New(sha256.New, kit.StringToBytes(token.secret))
	if _, err := hc.Write(kit.StringToBytes(hps)); err != nil {
		return nil, err
	} else {
		token.Sign = base64.StdEncoding.EncodeToString(hc.Sum(nil))
	}

	// format to xxx.xxx.xxx
	token.token = fmt.Sprintf("%s.%s", hps, token.Sign)
	return token, nil
}

func Check(token, secret string) (*Token, error) {
	if check != nil {
		return check(token, secret)
	} else {
		return defaultCheck(token, secret)
	}
}

func initTokenForOptions(opts ...Option) *Token {
	token := &Token{}
	token.Internal = make(map[string]string)
	token.External = make(map[string]string)

	for _, opt := range opts {
		opt(token)
	}

	if len(token.Typ) == 0 {
		token.Typ = typ
	}

	if len(token.Alg) == 0 {
		token.Alg = alg
	}

	if len(token.Iss) == 0 {
		token.Iss = iss
	}

	if len(token.Sub) == 0 {
		token.Sub = sub
	}

	if len(token.Aud) == 0 {
		token.Aud = aud
	}

	if token.Exp == 0 {
		token.Exp = exp
	}

	now := time.Now().Unix()

	if token.Nbf == 0 {
		token.Nbf = now
	}

	if token.Iat == 0 {
		token.Iat = now
	}

	if len(token.Jti) == 0 {
		token.Jti = strconv.Itoa(int(now))
	}

	return token
}

func defaultCheck(token, secret string) (*Token, error) {

	// format token check
	if !strings.Contains(token, ".") {
		return nil, InvalidToken
	}

	// item check
	item := strings.Split(token, ".")
	if len(item) < 3 {
		return nil, InvalidToken
	}

	// join header and payload for '.'
	headerItem, payloadItem, signItem := item[0], item[1], item[2]
	hps := fmt.Sprintf("%s.%s", headerItem, payloadItem)
	hc := hmac.New(sha256.New, []byte(secret))
	if _, err := hc.Write(kit.StringToBytes(hps)); err != nil {
		return nil, err
	}

	// signature check
	if signItem != base64.StdEncoding.EncodeToString(hc.Sum(nil)) {
		return nil, VerifyFailed
	}

	// decode header
	var h Header
	if hb, err := base64.StdEncoding.DecodeString(headerItem); err != nil {
		return nil, err
	} else {
		if err := kit.JsonDecoding(hb, &h); err != nil {
			return nil, err
		}
	}

	// decode payload
	var p Payload
	if pb, err := base64.StdEncoding.DecodeString(payloadItem); err != nil {
		return nil, err
	} else {
		if err := kit.JsonDecoding(pb, &p); err != nil {
			return nil, err
		}
	}

	// check jwt nbf
	if p.Nbf <= 0 {
		return nil, InvalidNbf
	}

	// has not reached the time
	now := time.Now().Unix()
	if p.Nbf > now {
		return nil, TokenNotReachedTime
	}

	// check jwt exp and iat
	if p.Exp <= 0 {
		return nil, InvalidExp
	}

	if p.Iat <= 0 {
		return nil, InvalidIat
	}

	// token has expired
	if now-p.Iat >= p.Exp {
		return nil, TokenHasExpired
	}

	return &Token{Header: h, Payload: p, Signature: Signature{Sign: signItem}, token: token, secret: secret}, nil
}
