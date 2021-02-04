// package auth knows how to validate jwts comming from Authorization headers in Gin
package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
)

const (
	KeyTypeRSA = "RSA"
)

// ExtractToken knows how to extract an authentication token from the Authorization header of a *gin.Context
func ExtractToken(c *gin.Context) string {
	authenticationHeader := c.GetHeader("authorization")
	if authenticationHeader == "" {
		return ""
	}

	rawToken := authenticationHeader[len("Bearer "):]

	return rawToken
}

// ValidateToken validates a raw JWT token based on provider data
func ValidateToken(providerData DiscoveryDocument, encodedToken string) (*jwt.Token, error) {
	claims := jwt.MapClaims{}
	claims["iss"] = providerData.Issuer

	token, err := jwt.ParseWithClaims(encodedToken, claims, func(token *jwt.Token) (interface{}, error) {
		algorithm := fmt.Sprintf("%s", token.Header["alg"])
		if algorithm == "none" {
			return nil, fmt.Errorf("algorithm none is not allowed")
		}

		keyID := fmt.Sprintf("%s", token.Header["kid"])

		var foundAlgorithm bool
		for _, supportedAlgorithm := range providerData.Algorithms {
			if algorithm == supportedAlgorithm {
				foundAlgorithm = true

				break
			}
		}
		if !foundAlgorithm {
			return nil, fmt.Errorf("algorithm not supported")
		}

		token.Method = jwt.GetSigningMethod(algorithm)

		certificate, err := providerData.getCertificate(keyID)

		if err != nil {
			return nil, fmt.Errorf("found no relevant certificate: %w", err)
		}

		return certificate, nil
	})

	if err != nil {
		return nil, fmt.Errorf("could not parse token: %w", err)
	}

	return token, nil
}

func (key *Key) getCertificate() string {
	return key.CertificateChain[0]
}

type JWKSResponse struct {
	Keys []Key `json:"keys"`
}

func (response *JWKSResponse) getKey(keyID string) (Key, error) {
	for _, potentialKey := range response.Keys {
		if potentialKey.KeyID == keyID {
			return potentialKey, nil
		}
	}

	return Key{}, fmt.Errorf("unable to find key with ID %s", keyID)
}

func (providerData *DiscoveryDocument) getCertificate(keyID string) (interface{}, error) {
	key, err := providerData.keys.getKey(keyID)
	if err != nil {
		return "", nil
	}

	decodedCertificate := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", key.getCertificate()))

	var certificate interface{}

	switch key.KeyType {
	case KeyTypeRSA:
		block, _ := pem.Decode(decodedCertificate)

		var cert *x509.Certificate
		cert, _ = x509.ParseCertificate(block.Bytes)

		certificate = cert.PublicKey.(*rsa.PublicKey)
	default:
		certificate = decodedCertificate
	}

	return certificate, nil
}

func fetchKeyMap(discoveryDocument *DiscoveryDocument) error {
	resp, err := http.Get(discoveryDocument.JWKSURL)
	if err != nil {
		return fmt.Errorf("could not get jwks_uri: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %w", err)
	}

	jwksResponse := JWKSResponse{}
	err = json.Unmarshal(body, &jwksResponse)
	if err != nil {
		return fmt.Errorf("error unmashaling body: %w", err)
	}

	discoveryDocument.keys = jwksResponse

	return nil
}

// FetchDiscoveryDocument extracts necessary information for token validation from a discovery endpoint
func FetchDiscoveryDocument(discoveryUrl string) (DiscoveryDocument, error) {
	providerData := DiscoveryDocument{}

	resp, err := http.Get(discoveryUrl)
	if err != nil {
		return providerData, fmt.Errorf("could not get %s: %w", discoveryUrl, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return providerData, fmt.Errorf("error reading body: %w", err)
	}

	err = json.Unmarshal(body, &providerData)
	if err != nil {
		return providerData, fmt.Errorf("error unmarshaling body: %w", err)
	}

	err = fetchKeyMap(&providerData)
	if err != nil {
		return providerData, fmt.Errorf("error fetching keymap: %w", err)
	}

	return providerData, nil
}
