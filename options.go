package jwt

type Option func(*Token)

func WithSecret(secret string) Option {
	return func(o *Token) {
		o.secret = secret
	}
}

func WithIss(iss string) Option {
	return func(o *Token) {
		o.Iss = iss
	}
}

func WithSub(sub string) Option {
	return func(o *Token) {
		o.Sub = sub
	}
}

func WithAud(aud string) Option {
	return func(o *Token) {
		o.Aud = aud
	}
}

func WithExp(exp int64) Option {
	return func(o *Token) {
		o.Exp = exp
	}
}

func WithNbf(nbf int64) Option {
	return func(o *Token) {
		o.Nbf = nbf
	}
}

func WithJti(jti string) Option {
	return func(o *Token) {
		o.Jti = jti
	}
}

func WithInternal(k, v string) Option {
	return func(o *Token) {
		o.Internal[k] = v
	}
}

func WithExternal(k, v string) Option {
	return func(o *Token) {
		o.External[k] = v
	}
}

func WithCheckFunc(handle CheckFunc) Option {
	return func(o *Token) {
		check = handle
	}
}
