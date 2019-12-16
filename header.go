package jwt

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
)

// jwt第一部分:header
// jwt的头部承载两部分信息：
// typ:声明类型,这里是jwt
// alg:声明加密的算法 通常直接使用 HMAC SHA256
// 完整的头部就像下面这样的JSON：
// {
// ....'typ': 'JWT',
// ....'alg': 'HS256'
// }
// 然后将头部进行base64加密（该加密是可以对称解密的),构成了第一部分
type Alg string

const (
	HmacSha256 Alg = "HMAC SHA256"
	HmacSha512 Alg = "HMAC SHA512"
	HmacMd5    Alg = "HMAC MD5"
)

var (
	algMapping = map[Alg]crypto.Hash{
		HmacSha256: crypto.SHA256,
		HmacSha512: crypto.SHA512,
		HmacMd5:    crypto.MD5,
	}
)

type Header struct {
	// 声明类型
	Typ string `json:"typ"`
	// 声明加密的算法 通常直接使用 HMAC SHA256
	Alg Alg `json:"alg"`
}

func (h *Header) String() string {
	hbs, _ := json.Marshal(h)
	return string(hbs)
}

func HeaderEncode(header *Header) string {
	hbs, _ := json.Marshal(header)
	return base64.StdEncoding.EncodeToString(hbs)
}

func HeaderDecode(header string) (*Header, error) {
	hbs, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}
	var h Header
	err = json.Unmarshal(hbs, &h)
	return &h, err
}
