package jwt

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
)

// jwt第三部分:signature
// jwt的第三部分是一个签证信息，这个签证信息由三部分组成：
// .1:header (base64)
// .2:payload (base64)
// .3:secret
// 这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，
// 然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分
// 将这三部分用"."连接成一个完整的字符串,构成了最终的jwt:xxxx.xxxx.xxxx
type Signature struct {
	// 签证
	Sign string `json:"sign"`
}

func (s *Signature) String() string {
	return s.Sign
}

func DoSignature(header string, payload string, hash crypto.Hash, secret string) (*Signature, error) {
	// join header and payload for '.', then do secret, get the jwt signature
	hps := fmt.Sprintf("%s.%s", header, payload)
	hc := hmac.New(hash.New, []byte(secret))
	if _, err := hc.Write([]byte(hps)); err != nil {
		return nil, err
	} else {
		return &Signature{Sign: base64.StdEncoding.EncodeToString(hc.Sum(nil))}, nil
	}
}
