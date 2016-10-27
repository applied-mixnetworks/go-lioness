package lioness

import (
	"bytes"
	"testing"
)

func TestBasicLionessEncrypt(t *testing.T) {
	var err error
	var key [LionessKeyLen]byte
	for i := 0; i < LionessKeyLen; i++ {
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

var result []byte

func BenchmarkLioness(b *testing.B) {
	var key [LionessKeyLen]byte
	for i := 0; i < LionessKeyLen; i++ {
		key[i] = byte(i) & 0xff
	}

	plaintext := []byte("Open, secure and reliable connectivity is necessary (although not   sufficient) to excercise the human rights such as freedom of   expression and freedom of association [FOC], as defined in the   Universal Declaration of Human Rights [UDHR].  The purpose of the   Internet to be a global network of networks that provides unfettered   connectivity to all users and for any content [RFC1958].  This   objective of stimulating global connectivity contributes to the   Internet's role as an enabler of human rights.  Next to that, the   strong commitment to security [RFC1984] [RFC3365] and privacy   [RFC6973] [RFC7258] in the Internet's architectural design contribute   to the strengthening of the Internet as a human rights enabling   environment.  One could even argue that the Internet is not only an   enabler of human rights, but that human rights lie at the basis of,   and are ingrained in, the architecture of the network.  Internet   connectivity increases the capacity for individuals to exercise their   rights, the core of the Internet, its architectural design is   therefore closely intertwined with the human rights framework   [CathFloridi].  The quintessential link between the Internet's   architecture and human rights has been argued by many.  [Bless] for   instance argues that, 'to a certain extent, the Internet and its   protocols have already facilitated the realization of human rights,   e.g., the freedom of assembly and expression.  In contrast, measures   of censorship and pervasive surveillance violate fundamental human   rights.'  [Denardis15] argues that 'Since the first hints of Internet   commercialization and internationalization,")
	cipher := NewLionessCipher(key, len(plaintext)) // key and block-size

	var err error
	var ciphertext []byte
	for i := 0; i < b.N; i++ {
		ciphertext, err = cipher.Encrypt(plaintext)
		if err != nil {
			panic(err)
		}
	}

	// always store the result to a package level variable
	// so the compiler cannot eliminate the Benchmark itself.
	result = ciphertext
}
