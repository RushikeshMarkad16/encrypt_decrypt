package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"database/sql"

	_ "github.com/lib/pq"
)

var db *sql.DB

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

func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Padding the plaintext to a multiple of the block size
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	paddedText := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, aes.BlockSize+len(paddedText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	return ciphertext, nil
}

func aesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := int(ciphertext[len(ciphertext)-1])
	return ciphertext[:len(ciphertext)-padding], nil
}

func encryptAndEncode(publicKey2 *rsa.PublicKey, message []byte) string {
	// Generate a random symmetric key for AES encryption
	symmetricKey := make([]byte, 32) // 32 bytes for AES-256
	if _, err := rand.Read(symmetricKey); err != nil {
		panic(err)
	}

	// Encrypt the symmetric key with the RSA public key
	encryptedSymmetricKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey2, symmetricKey)
	if err != nil {
		panic(err)
	}

	// Encrypt the actual data with the symmetric key using AES
	ciphertext, err := aesEncrypt(symmetricKey, message)
	if err != nil {
		panic(err)
	}

	// Combine the encrypted symmetric key and the AES-encrypted data
	combined := append(encryptedSymmetricKey, ciphertext...)

	// Base64 encode and print the result
	encodedResult := base64.StdEncoding.EncodeToString(combined)

	return encodedResult
}

func decryptAndDecode(privateKey *rsa.PrivateKey, encodedResult string) []byte {
	// Decrypt and decode
	decodedResult, err := base64.StdEncoding.DecodeString(encodedResult)
	if err != nil {
		panic(err)
	}

	decryptedSymmetricKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedResult[:privateKey.Size()])
	if err != nil {
		panic(err)
	}

	decryptedMessage, err := aesDecrypt(decryptedSymmetricKey, decodedResult[privateKey.Size():])
	if err != nil {
		panic(err)
	}

	return decryptedMessage
}

func configDB() {

	// Connection parameters
	connStr := "user=postgres dbname=test1 password=postgres sslmode=disable"
	var err error
	// Open a database connection
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to the database")

}

func storeToDb(encodedResult string) {
	// Perform an insert operation
	insertQuery := `INSERT INTO encode (encoded_value,timestamp) VALUES ($1,$2)`
	result, err := db.Exec(insertQuery, encodedResult, time.Now())
	if err != nil {
		fmt.Println("Error inserting data : ", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Inserted %d rows\n", rowsAffected)
}

type EncodeData struct {
	EncodedValue string
	Timestamp    time.Time
}

func GetFromDb() EncodeData {
	selectQuery := `SELECT * FROM encode ORDER BY timestamp DESC LIMIT 1;`
	rows, err := db.Query(selectQuery)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var encodeData EncodeData

	for rows.Next() {
		err := rows.Scan(&encodeData.EncodedValue, &encodeData.Timestamp)
		if err != nil {
			log.Fatal(err)
		}
	}
	return encodeData

}

func main() {
	configDB()
	defer db.Close()
	privateKey2 := generateRSAPrivateKey()
	encodePrivateKey(privateKey2, "private_key2.pem")
	publicKey2 := &privateKey2.PublicKey

	encodePublicKey(publicKey2, "public_key2.pem")

	message := []byte(`-----BEGIN RSA PRIVATE KEY-----
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

	encodedResult := encryptAndEncode(publicKey2, message)

	// Insert to DB
	storeToDb(encodedResult)

	// Get from database
	encodeData := GetFromDb()

	decryptedMessage := decryptAndDecode(privateKey2, encodeData.EncodedValue)

	fmt.Println("Decrypted message:", string(decryptedMessage))
}
