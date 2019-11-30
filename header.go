package jwt

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
type Header struct {
	// 声明类型
	Typ string `json:"typ"`
	// 声明加密的算法 通常直接使用 HMAC SHA256
	Alg string `json:"alg"`
}
