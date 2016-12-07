package lioness

import (
	"errors"

	"git.schwanenlied.me/yawning/chacha20"
	"github.com/minio/blake2b-simd"
)

const (
	chacha20NonceLen = 8
	chacha20KeyLen   = 32
	blake2bKeyLen    = 64
	secretKeyLen     = 40
)

type Chacha20Blake2bLionessCipher struct {
	cipher *Cipher
	k1     [secretKeyLen]byte
	k2     [blake2bKeyLen]byte
	k3     [secretKeyLen]byte
	k4     [blake2bKeyLen]byte
}

func NewChacha20Blake2bLionessCipher(key []byte, blockSize int) *Chacha20Blake2bLionessCipher {
	if blockSize < chacha20KeyLen+chacha20NonceLen {
		fmt.Errorf("Specified blocksize %d is smaller than minimum %d", blockSize, chacha20KeyLen+chacha20NonceLen)
	}

    c := Chacha20Blake2bLionessCipher{
    }
    cipher = NewLionessCipher(key, blockSize, secretKeyLen, hashKeyLen, XORKeyStreamFunc, HMACFunc),

	return &c
}

func (c *Cipher) StreamCipherXor() {
	chacha, err := chacha20.NewCipher(tmp[chachaNonceLen:chachaNonceLen+chachaKeyLen], tmp[:chachaNonceLen])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(r, r)
}

func (c *Cipher) Encrypt(block []byte) ([]byte, error) {
	cipher = NewLionessCipher()

}

type XORKeyStreamFunc func(dst, src []byte)
type HMACFunc func(size int, key []byte) []byte

// LionessCipher allows you to encrypt/decrypt large blocks
type Cipher struct {
	blockSize int
	k1        []byte
	k2        []byte
	k3        []byte
	k4        []byte
}

// NewCipher creates a new Cipher struct for encryption/decryption
func NewLionessCipher(key []byte, blockSize int, secretKeyLen, hashKeyLen int, xorStream XORKeyStreamFunc, hmac HMACFunc) *Cipher {
	if blockSize <= minBlockSize {
		return nil
	}
	c := LionessCipher{
		blockSize: blockSize,
	}
	copy(c.k1[:], key[:secretKeyLen])
	copy(c.k2[:], key[secretKeyLen:secretKeyLen+hashKeyLen])
	copy(c.k3[:], key[secretKeyLen+hashKeyLen:secretKeyLen*2+hashKeyLen])
	copy(c.k4[:], key[(2*secretKeyLen+hashKeyLen):hashKeyLen+(2*secretKeyLen+hashKeyLen)])
	return &c
}

// Encrypt encrypts a block
func (c *Cipher) Encrypt(block []byte) ([]byte, error) {
	if len(block) != c.blockSize {
		return nil, errors.New("input not equal to block size")
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
		return nil, err
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
		return nil, err
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
		return nil, errors.New("input not equal to block size")
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
		return nil, err
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
		return nil, err
	}
	chacha.XORKeyStream(r, r)

	out := make([]byte, c.blockSize)
	copy(out, l)
	copy(out[lSize:], r)
	return out, nil
}
