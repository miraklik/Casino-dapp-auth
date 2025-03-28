package utils

import (
	"casino-web3/config"
	"casino-web3/db"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var cfg config.Config

func GenerateToken(user db.User) (string, error) {
	tokenLifespanStr := cfg.JWT.Lifespan
	if tokenLifespanStr == "" {
		return "", fmt.Errorf("TOKEN_HOUR_LIFESPAN is not set")
	}

	tokenLifespan, err := strconv.Atoi(tokenLifespanStr)
	if err != nil {
		log.Printf("Error converting TOKEN_HOUR_LIFESPAN: %v", err)
		return "", err
	}

	claims := jwt.MapClaims{
		"authorized": true,
		"id":         user.ID,
		"exp":        time.Now().Add(time.Hour * time.Duration(tokenLifespan)).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	apiSecret := cfg.JWT.Secret
	if apiSecret == "" {
		return "", fmt.Errorf("API_SECRET is not set")
	}

	signedToken, err := token.SignedString([]byte(apiSecret))
	if err != nil {
		log.Printf("Error signing the token: %v", err)
		return "", err
	}

	return signedToken, nil
}

func ValidateToken(tokenStr, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrInvalidKey
	}

	return claims, nil
}

func GetToken(c *gin.Context) (*jwt.Token, error) {
	tokenString := getTokenFromRequest(c)
	if tokenString == "" {
		return nil, errors.New("token is missing from the request")
	}

	apiSecret := cfg.JWT.Secret
	if apiSecret == "" {
		return nil, fmt.Errorf("API_SECRET is not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(apiSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	return token, nil
}

func getTokenFromRequest(c *gin.Context) string {
	bearerToken := c.Request.Header.Get("Authorization")

	splitToken := strings.Split(bearerToken, " ")
	if len(splitToken) == 2 {
		return splitToken[1]
	}

	return ""
}
