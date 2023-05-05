package main

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

var jwtKey = []byte("secret_key")

var redisClient = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // no password set
	DB:       0,  // use default DB
})

type TokenPair struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func main() {
	// clear Redis refresh tokens
	emptyRedisRefreshTokens(redisClient)

	// test login and refresh token
	tp, err := login("dummy", "dummy", redisClient)
	if err != nil {
		fmt.Println("Login error:", err)
	}

	// Print Login & refresh token
	fmt.Println("\n Login token:", tp.Token)
	fmt.Println("\n Refresh token:", tp.RefreshToken)

	// test refresh token
	tp, err = refresh(tp.RefreshToken, redisClient)
	if err != nil {
		fmt.Println("Refresh error:", err)
	}

	// Print new Login & refresh token
	fmt.Println("\n New token:", tp.Token)
	fmt.Println("\n New refresh token:", tp.RefreshToken)
}

func emptyRedisRefreshTokens(redisClient *redis.Client) error {
	ctx := context.Background()
	iter := redisClient.Scan(ctx, 0, "*", 0).Iterator()
	for iter.Next(ctx) {
		err := redisClient.Del(ctx, iter.Val()).Err()
		if err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return nil
}

func login(username string, password string, redisClient *redis.Client) (*TokenPair, error) {
	if username != "dummy" || password != "dummy" {
		return nil, fmt.Errorf("invalid credentials")
	}

	// create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(), // token expires in 24 hours
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	// create refresh token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	// persist refresh token to Redis
	err = redisClient.Set(context.Background(), refreshTokenString, 1, time.Hour*24*7).Err() // refresh token expires in 7 days
	if err != nil {
		return nil, err
	}

	return &TokenPair{tokenString, refreshTokenString}, nil
}

func refresh(refreshTokenString string, redisClient *redis.Client) (*TokenPair, error) {
	// parse and validate refresh token
	_, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		// validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}

	// check if refresh token is in Redis
	exists, err := redisClient.Exists(context.Background(), refreshTokenString).Result()
	if err != nil || exists == 0 {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	// delete old refresh token from Redis
	err = redisClient.Del(context.Background(), refreshTokenString).Err()
	if err != nil {
		return nil, err
	}

	// create new JWT token
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(), // token expires in 24 hours
	})
	newTokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	// create new refresh token
	newRefreshToken := jwt.New(jwt.SigningMethodHS256)
	newRefreshTokenString, err := newRefreshToken.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	// persist new refresh token to Redis
	err = redisClient.Set(context.Background(), newRefreshTokenString, 1, time.Hour*24*7).Err() // refresh token expires in 7 days
	if err != nil {
		return nil, err
	}

	return &TokenPair{newTokenString, newRefreshTokenString}, nil
}
