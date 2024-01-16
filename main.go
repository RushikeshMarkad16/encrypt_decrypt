package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func generateRSAPrivateKey() *rsa.PrivateKey {
	// Generate a new RSA private key with 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		return nil
	}
	return privateKey
}

func encodePrivateKey(privateKey *rsa.PrivateKey, filename string) {
	// Encode the private key to the PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}

	pem.Encode(privateKeyFile, privateKeyPEM)
	privateKeyFile.Close()
}

func encodePublicKey(publicKey *rsa.PublicKey, filename string) {
	// Encode the public key to the PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating public key file:", err)
		os.Exit(1)
	}
	pem.Encode(publicKeyFile, publicKeyPEM)
	publicKeyFile.Close()
}

func encrypt(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) (string, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	// privateKey1 := generateRSAPrivateKey()
	// encodePrivateKey(privateKey1, "private_key1.pem")

	privateKey2 := generateRSAPrivateKey()
	encodePrivateKey(privateKey2, "private_key2.pem")
	publicKey2 := &privateKey2.PublicKey

	fmt.Println("size : ", publicKey2.Size())

	encodePublicKey(publicKey2, "public_key2.pem")

	msg := []byte(`-----BEGIN RSA PRIVATE KEY-----
	MIIEowIBAAKCAQEAt7arlt5MBvdM3B98K84JkpSg8KGbRXi9FtPTFzH8mYK1vdZ0
	kkMyOzNVIQU8V2wUu4zGvC1qXoeBSZDvZavzZHSNtO3rQMp8uoNVKs/DD7ZprCkB
	AjfWEmtP1qhbZBiLMHaufpSREyXV6FcZukvudent4vPl2ie8gDQqbXH0EBloROEG
	2U3pzARLkBtBmgqpuq1jpmhSZ9teysJzEQUU95M2e93qkLFLDehPdasg+XFd9nUV
	RigYPPyRx0BfecWG0En8ePcv3lZt3tkrQeGC/hekfmNjrk/vbK8D0c3aZRYeRSrI
	g8ba5Fx8a0ZS5+su6KCtjgtWh3QMyuUhLLQ2fQIDAQABAoIBAGyxALgT8Ts12R1q
	61YnYnZ8xPNZSbpCgu0ciglxI5fXQ5t7ZCCc7P0lk7ojlN3MLkAAPBxdak9fMFjM
	DTdEEo5efvCKyuLcagsXZK4dmbSUIdUftV8QlfDz2JqRpPCFrOQRc4+kami/u9zo
	m2ojPoQ40OuzjUwSsm3Pb0KtZs6WmO5LKqweJJEuGJMmJ54op+BLBkOqFhJIQzeE
	KBdPetiBScFFFz4VlnVKuOYEoBDrFZSiIvtNJ92ZgeEvh4JIV61yIQAAabnlhvQu
	V7BRv6Vypm0Gnc8s0++slsrE19e02gl5DjJSC5XSgkOI+YikWtXkpaO5jB/ESokS
	eAMzeqkCgYEA04SbtdiIxJjzc/BU8zDmiY4zmYhTZLwD5pPwyyXhicSYowpGb25F
	QPu3OHC7N6j4uEmFYGZyAQJlIwKGGlh+XQJkEzggrEn3nq+LFhGb+fJ3ulB9oHXB
	/cCo/58U8vXkwD3QoxhBERiB75WIDJwj8QXC0RfU0TZzySyk+bHyD3MCgYEA3lkq
	6e6AqTzs4y7otnY9B5ErRUKd7d3szGwQhrZPQBc8G/oVWFUOgbaYkveXH0xbZTmi
	cr+R8RNPxip8tHyW8k5lAPESc7f5p89qvOW8EwpDO0xNFYOeftPAx+w85PmB+9zW
	wudXetv9QGfbyxXTE53BrBPDj7nsS+2at+AYRk8CgYA9bM0rSe6t6R0KFkkVNqY8
	XCdv9r8BCfi4BU5wMFgHAiixcFJ0GbnS3UagBVzZFSDlo7QwApAo6uEkAZ+gFwLb
	T85wJmSWpARc+O2TQxngxCEw4h8Zchkb788kLLaQuAfuLAVi17BNnqhdQzd3MgDe
	BaZFwn3zI7UMPwLJ4HtDMQKBgQCcJXKFpgCk2SxivuaefJqPXdtNYGMYUOmjBaD1
	ecJd9/M2koG67sCpR1oOm+F9EVp90+PJQc9zxWQYfm3lMjmvIG6+Io4axfCFcJw8
	2/kgRezBD+xyV2RPHNYdkEGTa8Vk4snPRjehCCzptgYcsM7yz67a8WY84QyYpdwp
	lS528QKBgH69DPkflIF30+2FNaYA4BwMqHoHP6UAiLD2B7ZWS8eqCCNCdpwmFZBx
	CFYRJY4Ec9ILvWCYGuF6yVp53Sk0k6/MRSL1+9rYvhUqNywDwSjxslz1N9ENW4zm
	QvJRzj1ree7m7kyNl+a8H7G/vUvU2t8tXt3Q26FTuaDg2vzzxfPm
	-----END RSA PRIVATE KEY-----`)

	// msg := []byte("This is a sample RSA PRIVATE KEY")

	// Encrypt with public key 1
	ciphertext, err := encrypt(publicKey2, msg)
	if err != nil {
		fmt.Println("error : ", err)
		return
	}
	fmt.Println("ciphertext : ", ciphertext)

	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	fmt.Println("encodedCiphertext : ", encodedCiphertext)

	// Base64 decode
	decodedCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println("decodedCiphertext : ", decodedCiphertext)

	// Decrypt with private key 1
	decryptedMessage, err := decrypt(privateKey2, decodedCiphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("decryptedMessage : ", decryptedMessage)

}
