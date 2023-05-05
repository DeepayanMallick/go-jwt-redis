package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

func TestRefresh(t *testing.T) {
	// initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// set up test refresh token
	testRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	testRefreshTokenString, err := testRefreshToken.SignedString(jwtKey)
	if err != nil {
		t.Errorf("Failed to sign test refresh token: %v", err)
	}
	redisClient.Set(context.Background(), testRefreshTokenString, "", time.Hour)

	// call refresh function with test refresh token
	newTokenPair, err := refresh(testRefreshTokenString, redisClient)
	if err != nil {
		t.Errorf("Refresh failed with error: %v", err)
	}

	// check that new token pair was returned
	if newTokenPair == nil {
		t.Errorf("Refresh did not return a new token pair")
	}

	// check that new token is valid
	_, err = jwt.Parse(newTokenPair.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		t.Errorf("New token is not valid: %v", err)
	}

	// check that new refresh token is valid
	_, err = jwt.Parse(newTokenPair.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		t.Errorf("New refresh token is not valid: %v", err)
	}

	// check that old refresh token was deleted
	exists, err := redisClient.Exists(context.Background(), testRefreshTokenString).Result()
	if err != nil || exists != 0 {
		t.Errorf("Old refresh token was not deleted from Redis")
	}

	// check that new refresh token was persisted in Redis
	exists, err = redisClient.Exists(context.Background(), newTokenPair.RefreshToken).Result()
	if err != nil || exists != 1 {
		t.Errorf("New refresh token was not persisted in Redis")
	}
}
