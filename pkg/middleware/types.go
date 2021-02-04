package middleware

import "io"

type JWTValidationOptions struct {
	Out io.Writer

	DiscoveryURL string
}

type IntrospectionMiddlewareOptions struct {
	Out io.Writer

	DiscoveryURL string
	ClientID     string
	ClientSecret string
}

type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	JWKSURL               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
	keys                  JWKSResponse
}

type Key struct {
	KeyID            string   `json:"kid"`
	KeyType          string   `json:"kty"`
	CertificateChain []string `json:"x5c"`
}
