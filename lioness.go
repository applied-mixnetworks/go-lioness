package lioness

import (
	"git.schwanenlied.me/yawning/chacha20"
	"github.com/minio/blake2b-simd"
)

const (
	lionessKeyLen  = 208
	chachaNonceLen = 8
	chachaKeyLen   = 32
	hashKeyLen     = 64 // blake2b key len
	secretKeyLen   = chachaKeyLen + chachaNonceLen
	minBlockSize   = secretKeyLen
)

type LionessCipher struct {
	blockSize int
	k1        [secretKeyLen]byte
	k2        [hashKeyLen]byte
	k3        [secretKeyLen]byte
	k4        [hashKeyLen]byte
}

func NewLionessCipher(key []byte, blockSize int) *LionessCipher {
	if blockSize <= minBlockSize || len(key) != lionessKeyLen {
		return nil
	}
	c := LionessCipher{
		blockSize: blockSize,
	}
	copy(c.k1[:], key[:secretKeyLen])
	copy(c.k2[:], key[secretKeyLen:hashKeyLen])
	copy(c.k3[:], key[secretKeyLen+hashKeyLen:secretKeyLen*2+hashKeyLen])
	copy(c.k4[:], key[(2*secretKeyLen+hashKeyLen):hashKeyLen+(2*secretKeyLen+hashKeyLen)])
	return &c
}

func (c *LionessCipher) Encrypt(message []byte) ([]byte, error) {
	lSize := secretKeyLen
	rSize := c.blockSize - lSize
	tmp := make([]byte, lSize)
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	copy(l, message[:lSize])
	copy(r, message[lSize:lSize+rSize])

	// R = R ^ S(L ^ K1)
	xorBytes(tmp, l, c.k1[:])
	// XXX why should we compose the nonce and key like this?
	chacha, err := chacha20.NewCipher(tmp[:chachaKeyLen], tmp[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K2, R)
	h := blake2b.NewMAC(uint8(lSize), c.k2[:hashKeyLen])
	//h.Reset()
	//h.Write(r)
	//tmp1 := h.Sum(nil)
	tmp1 := h.Sum(r)
	xorBytes(l, message[:lSize], tmp1)

	// R = R ^ S(L ^ K3)
	xorBytes(tmp, l, c.k3[:])
	// XXX why should we compose the nonce and key like this?
	chacha, err = chacha20.NewCipher(tmp[:chachaKeyLen], tmp[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K4, R)
	h = blake2b.NewMAC(uint8(lSize), c.k4[:hashKeyLen])
	//h.Reset()
	//h.Write(r)
	//tmp = h.Sum(nil)
	tmp = h.Sum(r)
	xorBytes(l, l, tmp[:lSize])

	out := make([]byte, c.blockSize)
	copy(out, l)
	copy(out[lSize:], r)
	return out, nil
}

func (c *LionessCipher) Decrypt(message []byte) ([]byte, error) {
	lSize := secretKeyLen
	rSize := c.blockSize - lSize
	tmp := make([]byte, lSize)
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	copy(r, message[lSize:rSize])

	// L = L ^ H(K4, R)
	h := blake2b.NewMAC(uint8(lSize), c.k4[:hashKeyLen])
	//h.Reset()
	//h.Write(r)
	//tmp = h.Sum(nil)
	tmp = h.Sum(r)
	xorBytes(l, message, tmp[:lSize])

	// R = R ^ S(L ^ K3)
	xorBytes(tmp, l, c.k3[:])
	// XXX why should we compose the nonce and key like this?
	chacha, err := chacha20.NewCipher(tmp[:chachaKeyLen], tmp[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(r, r)

	// L = L ^ H(K2, R)
	h = blake2b.NewMAC(uint8(lSize), c.k2[:hashKeyLen])
	//h.Reset()
	//h.Write(r)
	//tmp = h.Sum(nil)
	tmp = h.Sum(r)
	xorBytes(l, l, tmp[:lSize])

	// R = R ^ S(L ^ K1)
	xorBytes(tmp, l, c.k1[:])
	// XXX why should we compose the nonce and key like this?
	chacha, err = chacha20.NewCipher(tmp[:chachaKeyLen], tmp[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	chacha.XORKeyStream(r, r)

	out := make([]byte, c.blockSize)
	copy(out, l)
	copy(out[lSize:], r)
	return out, nil
}
