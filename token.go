package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	typ = "JWT"
	iss = "default"
	sub = "default"
	aud = "default"
	exp = 7200
)

var (
	checkFunMap          sync.Map
	InvalidToken         = errors.New("jwt token invalid")
	VerifyFailed         = errors.New("jwt token verify failed")
	InvalidAlg           = errors.New("jwt token header alg invalid")
	InvalidNbf           = errors.New("jwt token payload nbf invalid")
	InvalidExp           = errors.New("jwt token payload exp invalid")
	InvalidIat           = errors.New("jwt token payload iat invalid")
	TokenNotReachedTime  = errors.New("jwt token authorization has not reached the time of entry into force")
	TokenHasExpired      = errors.New("jwt token has expired")
	TokenSecretKeyEmpty  = errors.New("jwt token secret key is empty")
	TokenCheckFunIsEmpty = errors.New("jwt token check fun is empty")
)

type CheckFunc func(token, secret string) (*Token, error)

// Token
type Token struct {
	*Header
	*Payload
	*Signature
	check  CheckFunc
	token  string
	secret string
}

func (t *Token) String() string {
	return t.token
}

func setCheckFun(token string, check CheckFunc) {
	hash := sha256.New()
	hash.Write([]byte(token))
	checkFunMap.Store(base64.StdEncoding.EncodeToString(hash.Sum(nil)), check)
}

func getCheckFun(token string) (CheckFunc, bool) {
	hash := sha256.New()
	hash.Write([]byte(token))
	check, ok := checkFunMap.Load(base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	if !ok {
		return nil, false
	}
	return check.(CheckFunc), true
}

func New(opts ...Option) (token *Token, err error) {
	// init
	token = initTokenForOptions(opts...)
	if token.secret == "" {
		return nil, TokenSecretKeyEmpty
	}
	// header
	header := HeaderEncode(token.Header)
	// payload
	payload := PayloadEncode(token.Payload)
	// get alg hash and signature
	if hash, ok := algMapping[token.Header.Alg]; !ok {
		return nil, InvalidAlg
	} else {
		token.Signature, err = DoSignature(header, payload, hash, token.secret)
	}
	// format to xxx.xxx.xxx
	token.token = fmt.Sprintf("%s.%s.%s", header, payload, token.Sign)
	// set the jwt check func name
	setCheckFun(token.token, token.check)
	return token, nil
}

func Check(token, secret string) (*Token, error) {
	check, ok := getCheckFun(token)
	if !ok {
		return nil, TokenCheckFunIsEmpty
	}
	return check(token, secret)
}

func initTokenForOptions(opts ...Option) (token *Token) {
	now := time.Now()
	token = &Token{
		Header: &Header{
			Typ: typ,
			Alg: HmacSha256,
		},
		Payload: &Payload{
			Iss:      iss,
			Sub:      sub,
			Aud:      aud,
			Exp:      exp,
			Nbf:      now,
			Iat:      now,
			Jti:      strconv.Itoa(int(now.Unix())),
			Internal: make(map[string]string),
			External: make(map[string]string),
		},
		Signature: &Signature{
			Sign: "",
		},
		check: defaultCheck,
	}
	for _, opt := range opts {
		opt(token)
	}
	return
}

func defaultCheck(token, secret string) (*Token, error) {

	// token format check
	if !strings.Contains(token, ".") {
		return nil, InvalidToken
	}

	// items check
	items := strings.Split(token, ".")
	if len(items) != 3 {
		return nil, InvalidToken
	}

	// get header/payload/sign
	headers, payloads, signs := items[0], items[1], items[2]

	// decode header
	header, err := HeaderDecode(headers)
	if err != nil {
		return nil, err
	}

	// get hash
	hash, ok := algMapping[header.Alg]
	if !ok {
		return nil, InvalidAlg
	}

	// do background sign
	sign, err := DoSignature(headers, payloads, hash, secret)
	if err != nil {
		return nil, err
	}

	// signature check
	if signs != sign.Sign {
		return nil, VerifyFailed
	}

	// decode payload
	payload, err := PayloadDecode(payloads)
	if err != nil {
		return nil, err
	}

	// check jwt nbf
	if payload.Nbf.Unix() <= 0 {
		return nil, InvalidNbf
	}

	// has not reached the time
	now := time.Now()
	if payload.Nbf.Unix() > now.Unix() {
		return nil, TokenNotReachedTime
	}

	// check jwt exp and iat
	if payload.Exp <= 0 {
		return nil, InvalidExp
	}

	if payload.Iat.Unix() <= 0 {
		return nil, InvalidIat
	}

	// token has expired
	if now.Sub(payload.Iat) >= payload.Exp {
		return nil, TokenHasExpired
	}

	return &Token{
		Header:    header,
		Payload:   payload,
		Signature: &Signature{Sign: signs},
		token:     token,
		secret:    secret,
	}, nil
}
