package utils

import (
	"casino-web3/config"
	"casino-web3/db"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type JWTService struct {
	cfg config.Config
}

func NewJWTService(cfg config.Config) *JWTService {
	return &JWTService{cfg: cfg}
}

func (j *JWTService) GenerateToken(user db.User) (string, error) {
	tokenLifespan, err := strconv.Atoi(j.cfg.JWT.Lifespan)
	if err != nil {
		return "", fmt.Errorf("invalid TOKEN_HOUR_LIFESPAN: %w", err)
	}

	claims := jwt.MapClaims{
		"authorized": true,
		"id":         user.ID,
		"exp":        time.Now().Add(time.Hour * time.Duration(tokenLifespan)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if j.cfg.JWT.Secret == "" {
		return "", errors.New("API_SECRET is not set")
	}

	return token.SignedString([]byte(j.cfg.JWT.Secret))
}

func (j *JWTService) ValidateToken(tokenStr string) (*jwt.Token, error) {
	if tokenStr == "" {
		return nil, errors.New("token is missing")
	}

	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.cfg.JWT.Secret), nil
	})
}

func GetTokenFromRequest(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

func (j *JWTService) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := GetTokenFromRequest(c)
		token, err := j.ValidateToken(tokenStr)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token claims"})
			return
		}

		c.Set("user_id", uint(claims["id"].(float64)))

		c.Next()
	}
}

func CurrentUser(c *gin.Context) (db.User, error) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		return db.User{}, errors.New("user_id not found in context")
	}

	userID, ok := userIDVal.(uint)
	if !ok {
		return db.User{}, errors.New("user_id type assertion failed")
	}

	user, err := db.GetUserById(userID)
	if err != nil {
		return db.User{}, err
	}

	return user, nil
}
