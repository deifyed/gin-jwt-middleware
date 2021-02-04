package middleware

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// JWTValidationMiddleware validates authorization header bearer JWT tokens and adds a "user" to the *gin.Context
func JWTValidationMiddleware(options JWTValidationOptions) gin.HandlerFunc {
	providerData, err := FetchDiscoveryDocument(options.DiscoveryURL)
	if err != nil {
		log.Panic("Could not fetch required provider data for JWT validation", err)
	}

	logger := log.New(options.Out, "IntrospectionMiddleware", log.Flags())

	return func(c *gin.Context) {
		encodedToken := ExtractToken(c)

		validToken, err := ValidateToken(providerData, encodedToken)
		if err != nil {
			logger.Println("error validating token: ", err)

			c.AbortWithStatus(401)
		} else {
			c.Set("user", validToken)

			c.Next()
		}
	}
}

// IntrospectionMiddleware validates the authorization header token using an introspection endpoint
func IntrospectionMiddleware(options IntrospectionMiddlewareOptions) gin.HandlerFunc {
	providerData, err := FetchDiscoveryDocument(options.DiscoveryURL)
	if err != nil {
		log.Panic("Could not fetch required provider data for JWT validation", err)
	}

	logger := log.New(options.Out, "IntrospectionMiddleware", log.Flags())

	return func(c *gin.Context) {
		encodedToken := ExtractToken(c)

		values := url.Values{}
		values.Add("client_id", options.ClientID)
		values.Add("client_secret", options.ClientSecret)
		values.Add("token", encodedToken)

		request, err := http.NewRequest(http.MethodPost, providerData.IntrospectionEndpoint, strings.NewReader(values.Encode()))
		if err != nil {
			logger.Println("error creating introspection request: ", err)

			return
		}

		client := http.Client{}

		response, err := client.Do(request)
		if err != nil {
			logger.Println("error posting token to introspection endpoint: ", err)

			return
		}

		if response.StatusCode != http.StatusOK {
			c.AbortWithStatus(http.StatusUnauthorized)

			logger.Println("error validating token: ", response.StatusCode)

			return
		}

		c.Next()
	}
}
