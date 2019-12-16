package jwt

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// jwt第二部分:payload
// 载荷就是存放有效信息的地方。这个名字像是特指飞机上承载的货品，这些有效信息包含三个部分
// .标准中注册的声明
// .公共的声明
// .私有的声明
//
// 标准中注册的声明 (建议但不强制使用) ：
// .iss: jwt签发者
// .sub: jwt所面向的用户
// .aud: 接收jwt的一方
// .exp: jwt的过期时间，这个过期时间必须要大于签发时间
// .nbf: 定义在什么时间之前，该jwt都是不可用的.
// .iat: jwt的签发时间
// .jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
//
// 公共的声明 ：
// .公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.
//
// 私有的声明 ：
// .私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。
//
// 定义一个payload:
// {
// ...."sub": "1234567890",
// ...."name": "Marcos",
// ...."admin": true
// }
// 然后将其进行base64加密，得到Jwt的第二部分
type Payload struct {
	// jwt签发者
	Iss string `json:"iss"`
	// jwt所面向的用户
	Sub string `json:"sub"`
	// 接收jwt的一方
	Aud string `json:"aud"`
	// jwt的过期时间，这个过期时间必须要大于签发时间(秒)
	Exp time.Duration `json:"exp"`
	// 定义在什么时间之前，该jwt都是不可用的(秒)
	Nbf time.Time `json:"nbf"`
	// jwt的签发时间(秒)
	Iat time.Time `json:"iat"`
	// jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
	Jti string `json:"jti"`
	// 内部声明
	Internal map[string]string `json:"internal"`
	// 外部声明
	External map[string]string `json:"external"`
}

func (p *Payload) String() string {
	pbs, _ := json.Marshal(p)
	return string(pbs)
}

func PayloadEncode(payload *Payload) string {
	pbs, _ := json.Marshal(payload)
	return base64.StdEncoding.EncodeToString(pbs)
}

func PayloadDecode(payload string) (*Payload, error) {
	pbs, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var p Payload
	err = json.Unmarshal(pbs, &p)
	return &p, err
}
