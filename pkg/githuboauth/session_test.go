package githuboauth

import (
	"sync"
	"testing"
)

func TestGenerateSessionSecretKey_Length(t *testing.T) {
	key, err := GenerateSessionSecretKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(key))
	}
}

func TestGenerateSessionEncryptionKey_Length(t *testing.T) {
	key, err := GenerateSessionEncryptionKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestGeneratedKeys_PassValidation(t *testing.T) {
	secretKey, err := GenerateSessionSecretKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	encKey, err := GenerateSessionEncryptionKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// F-B: Generated keys should be directly usable with NewSessionStore
	_, err = NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "test",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("generated keys should pass validation: %v", err)
	}
}

func TestKeyRoundTrip_Base64(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()

	// Encode to base64 for storage
	encodedSecret := EncodeKeyToBase64(secretKey)
	encodedEnc := EncodeKeyToBase64(encKey)

	// Decode back
	decodedSecret, err := DecodeKeyFromBase64(encodedSecret)
	if err != nil {
		t.Fatalf("failed to decode secret key: %v", err)
	}
	decodedEnc, err := DecodeKeyFromBase64(encodedEnc)
	if err != nil {
		t.Fatalf("failed to decode encryption key: %v", err)
	}

	// Decoded keys should pass validation
	_, err = NewSessionStore(&SessionStoreOptions{
		SecretKey:     decodedSecret,
		EncryptionKey: decodedEnc,
		CookieName:    "test",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("decoded keys should pass validation: %v", err)
	}
}

func TestNewSessionStore_WrongSecretKeyLength(t *testing.T) {
	_, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     make([]byte, 32), // wrong: need 64
		EncryptionKey: make([]byte, 32),
		CookieName:    "test",
	})
	if err == nil {
		t.Fatal("expected error for wrong secret key length")
	}
}

func TestNewSessionStore_WrongEncryptionKeyLength(t *testing.T) {
	_, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     make([]byte, 64),
		EncryptionKey: make([]byte, 16), // wrong: need 32
		CookieName:    "test",
	})
	if err == nil {
		t.Fatal("expected error for wrong encryption key length")
	}
}

func TestSessionData_ConcurrentAccess(t *testing.T) {
	session := &Session{
		Data: make(map[string]any),
	}

	var wg sync.WaitGroup
	// Concurrent writes
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session.SetData("key", i)
		}(i)
	}
	// Concurrent reads
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.GetData("key")
		}()
	}
	wg.Wait()

	// Verify data is readable after concurrent access
	_, ok := session.GetData("key")
	if !ok {
		t.Error("expected key to exist after concurrent writes")
	}
}

func TestSession_HasUserInfo(t *testing.T) {
	s := &Session{}
	if s.HasUserInfo() {
		t.Error("expected HasUserInfo() to be false for new session")
	}

	s.UserInformation = &UserInformation{
		Profile: &UserProfile{Login: "test"},
	}
	if !s.HasUserInfo() {
		t.Error("expected HasUserInfo() to be true after setting user info")
	}
}

func TestSession_SetUserInfo_CachesInStore(t *testing.T) {
	secretKey, _ := GenerateSessionSecretKey()
	encKey, _ := GenerateSessionEncryptionKey()
	store, err := NewSessionStore(&SessionStoreOptions{
		SecretKey:     secretKey,
		EncryptionKey: encKey,
		CookieName:    "test",
		CookieDomain:  "localhost",
		MaxAge:        3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := &Session{
		Data:      make(map[string]any),
		store:     store,
		sessionID: "test-session-id",
	}

	userInfo := &UserInformation{
		Profile: &UserProfile{Login: "testuser"},
	}
	session.SetUserInfo(userInfo)

	// Verify it's in the cache
	cached, ok := store.userInfoCache.Get("test-session-id")
	if !ok {
		t.Fatal("expected user info to be cached")
	}
	if cached.Profile.Login != "testuser" {
		t.Errorf("expected cached login %q, got %q", "testuser", cached.Profile.Login)
	}
}

func TestGenerateSessionID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate session ID generated: %s", id)
		}
		seen[id] = true
	}
}
