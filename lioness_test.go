package lioness

import (
	"bytes"
	"testing"
)

func TestBasicLionessEncrypt(t *testing.T) {
	var err error
	key := make([]byte, lionessKeyLen)
	for i := 0; i < lionessKeyLen; i++ {
		key[i] = byte(i) & 0xff
	}

	plaintext := []byte("'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st")
	cipher := NewLionessCipher(key, len(plaintext)) // key and block-size
	// Encrypt and see if it blows up.
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	message := []byte{}
	message, err = cipher.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(message, plaintext) {
		t.Error("decrypted ciphertext not equal plaintext")
		t.Fail()
	}
}
