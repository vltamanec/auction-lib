package auth

import (
	"errors"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func ParseToken(tokenStr string) (*Claims, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("missing JWT_SECRET")
		return nil, errors.New("missing JWT_SECRET")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid tokenт")
	}

	claimsMap, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims structure")
	}

	return &Claims{
		UserID: int64((*claimsMap)["user_id"].(float64)),
		Role:   (*claimsMap)["role"].(string),
	}, nil
}
