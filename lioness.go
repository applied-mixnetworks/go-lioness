package lioness

import (
	"errors"
	"fmt"

	"git.schwanenlied.me/yawning/chacha20"
	"github.com/minio/blake2b-simd"
)

const (
	// KeyLen is the length of our Lioness key
	KeyLen         = 208
	chachaNonceLen = 8
	chachaKeyLen   = 32
	hashKeyLen     = 64 // blake2b key len
	secretKeyLen   = chachaKeyLen + chachaNonceLen
	// MinBlockSize is the minimum block size the cipher can process
	MinBlockSize = secretKeyLen
)

// Cipher allows you to encrypt/decrypt large blocks
type Cipher struct {
	blockSize int
	k1        [secretKeyLen]byte
	k2        [hashKeyLen]byte
	k3        [secretKeyLen]byte
	k4        [hashKeyLen]byte
}

// NewCipher creates a new Cipher struct for encryption/decryption
func NewCipher(key [KeyLen]byte, blockSize int) (*Cipher, error) {
	// The block size must accomodate |L| = S_KEY_LEN, along with
	// |R| > 0, and the key should be the correct size.
	if blockSize <= MinBlockSize {
		return nil, fmt.Errorf("LIONESS block size mismatch error: %d <= %d min block size", blockSize, MinBlockSize)
	}
	c := Cipher{
		blockSize: blockSize,
	}
	copy(c.k1[:], key[:secretKeyLen])
	copy(c.k2[:], key[secretKeyLen:secretKeyLen+hashKeyLen])
	copy(c.k3[:], key[secretKeyLen+hashKeyLen:secretKeyLen*2+hashKeyLen])
	copy(c.k4[:], key[(2*secretKeyLen+hashKeyLen):hashKeyLen+(2*secretKeyLen+hashKeyLen)])
	return &c, nil
}

// Encrypt encrypts a block
func (c *Cipher) Encrypt(block []byte) ([]byte, error) {
	if len(block) != c.blockSize {
		return nil, errors.New("LIONESS Encrypt failed: input block size is not equal to block size")
	}

	lSize := secretKeyLen
	rSize := c.blockSize - lSize
	tmp := make([]byte, lSize)
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	copy(r, block[lSize:lSize+rSize])

	// R = R ^ S(L ^ K1)
	XorBytes(tmp, block[:lSize], c.k1[:])
	chacha, err := chacha20.NewCipher(tmp[chachaNonceLen:chachaNonceLen+chachaKeyLen], tmp[:chachaNonceLen])
	if err != nil {
		return nil, fmt.Errorf("LIONESS Encrypt failed: %v", err)
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K2, R)
	h := blake2b.NewMAC(uint8(lSize), c.k2[:hashKeyLen])
	h.Reset()
	h.Write(r)
	tmp1 := h.Sum(nil)
	XorBytes(l, block[:lSize], tmp1)

	// R = R ^ S(L ^ K3)
	XorBytes(tmp, l, c.k3[:])
	chacha, err = chacha20.NewCipher(tmp[chachaNonceLen:chachaNonceLen+chachaKeyLen], tmp[:chachaNonceLen])
	if err != nil {
		return nil, fmt.Errorf("LIONESS Encrypt failed: %v", err)
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K4, R)
	h = blake2b.NewMAC(uint8(lSize), c.k4[:hashKeyLen])
	h.Reset()
	h.Write(r)
	tmp = h.Sum(nil)
	XorBytes(l, l, tmp[:lSize])

	out := make([]byte, c.blockSize)
	copy(out, l)
	copy(out[lSize:], r)

	return out, nil
}

// Decrypt decrypts a block
func (c *Cipher) Decrypt(block []byte) ([]byte, error) {
	if len(block) != c.blockSize {
		return nil, errors.New("LIONESS Decrypt failed: input block size is not equal to block size")
	}

	lSize := secretKeyLen
	rSize := c.blockSize - lSize
	tmp := make([]byte, lSize)
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	copy(r, block[lSize:lSize+rSize])

	// L = L ^ H(K4, R)
	h := blake2b.NewMAC(uint8(lSize), c.k4[:hashKeyLen])
	h.Reset()
	h.Write(r)
	tmp = h.Sum(nil)
	XorBytes(l, block, tmp[:lSize])

	// R = R ^ S(L ^ K3)
	XorBytes(tmp, l, c.k3[:])
	chacha, err := chacha20.NewCipher(tmp[chachaNonceLen:chachaNonceLen+chachaKeyLen], tmp[:chachaNonceLen])
	if err != nil {
		return nil, fmt.Errorf("LIONESS Decrypt failed: %v", err)
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K2, R)
	h = blake2b.NewMAC(uint8(lSize), c.k2[:hashKeyLen])
	h.Reset()
	h.Write(r)
	tmp = h.Sum(nil)
	XorBytes(l, l, tmp[:lSize])

	// R = R ^ S(L ^ K1)
	XorBytes(tmp, l, c.k1[:])
	chacha, err = chacha20.NewCipher(tmp[chachaNonceLen:chachaNonceLen+chachaKeyLen], tmp[:chachaNonceLen])
	if err != nil {
		return nil, fmt.Errorf("LIONESS Decrypt failed: %v", err)
	}
	chacha.XORKeyStream(r, r)

	out := make([]byte, c.blockSize)
	copy(out, l)
	copy(out[lSize:], r)
	return out, nil
}
