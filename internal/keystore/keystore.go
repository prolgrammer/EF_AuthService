package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	rsaKeyBits = 2048

	privExt = ".pem"
	pubExt  = ".pub"
)

// Key — единица ключевого материала с метаданными.
type Key struct {
	KID       string
	Private   *rsa.PrivateKey
	Public    *rsa.PublicKey
	CreatedAt time.Time
	NotAfter  time.Time // verifying TTL: после этого ключ удаляется
}

// JWK — RFC 7517 minimal-fields для RS256 verifying.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS — ответ /jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Store — хранилище ключей с потокобезопасным доступом.
type Store struct {
	dir         string
	rotateEvery time.Duration
	overlapFor  time.Duration
	logger      *zap.Logger

	mu     sync.RWMutex
	keys   map[string]*Key // kid -> Key
	active string          // kid активного

	rotations func()    // metric callback (KeyRotations.Inc)
	gauge     func(int) // metric callback (ActiveJWKKeys.Set)
}

// Options — параметры создания Store.
type Options struct {
	Dir         string
	RotateEvery time.Duration
	OverlapFor  time.Duration
	Logger      *zap.Logger
	OnRotate    func()
	SetGauge    func(int)
}

// New создаёт Store, читает существующие ключи и при необходимости генерирует
// первый ключ.
func New(opts Options) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir keys: %w", err)
	}
	s := &Store{
		dir:         opts.Dir,
		rotateEvery: opts.RotateEvery,
		overlapFor:  opts.OverlapFor,
		logger:      opts.Logger,
		keys:        make(map[string]*Key),
		rotations:   opts.OnRotate,
		gauge:       opts.SetGauge,
	}
	if s.rotations == nil {
		s.rotations = func() {}
	}
	if s.gauge == nil {
		s.gauge = func(int) {}
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	if len(s.keys) == 0 {
		if _, err := s.rotate(time.Now()); err != nil {
			return nil, fmt.Errorf("initial key gen: %w", err)
		}
	}
	s.gauge(s.keyCount())
	return s, nil
}

// SigningKey возвращает kid и приватник для подписи нового токена.
func (s *Store) SigningKey() (string, *rsa.PrivateKey) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := s.keys[s.active]
	return k.KID, k.Private
}

// PublicKey возвращает publicKey по kid (для verify). Если ключа нет — ошибка.
func (s *Store) PublicKey(kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return k.Public, nil
}

// JWKS возвращает все publicKey в формате JWKS.
func (s *Store) JWKS() JWKS {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, len(s.keys))}
	for _, k := range s.keys {
		out.Keys = append(out.Keys, jwkFromPublic(k.KID, k.Public))
	}
	sort.Slice(out.Keys, func(i, j int) bool { return out.Keys[i].Kid < out.Keys[j].Kid })
	return out
}

// Run запускает фоновую ротацию. Завершается по ctx.Done.
func (s *Store) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(s.rotateEvery / 2) // проверяем чаще ротации, чтобы не пропустить overlap-cleanup
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			s.maybeRotate(now)
			s.gcExpired(now)
			s.gauge(s.keyCount())
		}
	}
}

func (s *Store) maybeRotate(now time.Time) {
	s.mu.RLock()
	active := s.keys[s.active]
	s.mu.RUnlock()
	if now.Sub(active.CreatedAt) < s.rotateEvery {
		return
	}
	if _, err := s.rotate(now); err != nil {
		s.logger.Error("key rotation failed", zap.Error(err))
		return
	}
	s.rotations()
}

func (s *Store) gcExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for kid, k := range s.keys {
		if kid == s.active {
			continue
		}
		if now.After(k.NotAfter) {
			delete(s.keys, kid)
			_ = os.Remove(filepath.Join(s.dir, kid+privExt))
			_ = os.Remove(filepath.Join(s.dir, kid+pubExt))
			s.logger.Info("expired signing key removed", zap.String("kid", kid))
		}
	}
}

// rotate — генерирует и сохраняет новый ключ, делает его активным.
func (s *Store) rotate(now time.Time) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("rsa gen: %w", err)
	}
	kid := makeKID(now)
	k := &Key{
		KID:       kid,
		Private:   priv,
		Public:    &priv.PublicKey,
		CreatedAt: now,
		NotAfter:  now.Add(s.rotateEvery + s.overlapFor),
	}
	if err := s.persistKey(k); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.keys[kid] = k
	s.active = kid
	s.mu.Unlock()
	s.logger.Info("signing key rotated", zap.String("kid", kid))
	return k, nil
}

func (s *Store) persistKey(k *Key) error {
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.Private),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return fmt.Errorf("marshal pub: %w", err)
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	if err := os.WriteFile(filepath.Join(s.dir, k.KID+privExt), privBytes, 0o600); err != nil {
		return fmt.Errorf("write priv: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, k.KID+pubExt), pubBytes, 0o644); err != nil {
		return fmt.Errorf("write pub: %w", err)
	}
	return nil
}

func (s *Store) loadFromDisk() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read keys dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), privExt) {
			continue
		}
		kid := strings.TrimSuffix(e.Name(), privExt)
		raw, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return fmt.Errorf("read priv %s: %w", kid, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return fmt.Errorf("invalid pem for %s", kid)
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse priv %s: %w", kid, err)
		}
		info, _ := e.Info()
		s.keys[kid] = &Key{
			KID:       kid,
			Private:   priv,
			Public:    &priv.PublicKey,
			CreatedAt: info.ModTime(),
			NotAfter:  info.ModTime().Add(s.rotateEvery + s.overlapFor),
		}
	}
	// активный — самый свежий
	var newest *Key
	for _, k := range s.keys {
		if newest == nil || k.CreatedAt.After(newest.CreatedAt) {
			newest = k
		}
	}
	if newest != nil {
		s.active = newest.KID
	}
	return nil
}

func (s *Store) keyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// makeKID — детерминированный, монотонный, UTC.
func makeKID(t time.Time) string {
	return "k-" + t.UTC().Format("20060102T150405.000")
}

// jwkFromPublic — RFC 7517 §4.
func jwkFromPublic(kid string, pub *rsa.PublicKey) JWK {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid, N: n, E: e}
}

// Thumbprint — RFC 7638; полезно в тестах и аудите.
func Thumbprint(jwk JWK) string {
	canonical := fmt.Sprintf(`{"e":"%s","kty":"%s","n":"%s"}`, jwk.E, jwk.Kty, jwk.N)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ErrNoActiveKey — sanity check при холодном старте без ключей.
var ErrNoActiveKey = errors.New("no active signing key")
