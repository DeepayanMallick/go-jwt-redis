package main

import (
	"testing"

	"github.com/go-redis/redis/v8"
)

func TestLogin(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Test with correct credentials
	tokenPair, err := login("dummy", "dummy", redisClient)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// Verify token pair is not nil
	if tokenPair == nil {
		t.Error("Expected token pair, but got nil")
	}

	// Verify token is not empty
	if tokenPair.Token == "" {
		t.Error("Expected non-empty token, but got empty")
	}

	// Verify refresh token is not empty
	if tokenPair.RefreshToken == "" {
		t.Error("Expected non-empty refresh token, but got empty")
	}

	// Test with incorrect credentials
	_, err = login("wrong", "credentials", redisClient)
	if err == nil {
		t.Error("Expected error, but got nil")
	}

	// Verify error message
	if err.Error() != "invalid credentials" {
		t.Errorf("Expected error message 'invalid credentials', but got %v", err)
	}
}
