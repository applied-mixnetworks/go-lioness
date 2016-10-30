package lioness

import (
	"bytes"
	"testing"
)

func TestBasicLionessEncrypt(t *testing.T) {
	var err error
	var key [KeyLen]byte
	for i := 0; i < KeyLen; i++ {
		key[i] = byte(i) & 0xff
	}

	plaintext := []byte("'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st")
	cipher := NewCipher(key, len(plaintext)) // key and block-size
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

var draftTestVectors = []struct {
	key   [KeyLen]byte
	block []byte
	want  []byte
}{
	{
		key: [KeyLen]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		block: []byte{
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
			0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
			0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
			0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
			0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
			0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
			0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
			0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
			0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
			0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
			0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
			0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
			0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
			0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
			0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
			0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
		},
		want: []byte{
			0x9b, 0xad, 0x42, 0xcf, 0x81, 0x92, 0xb4, 0x9,
			0x64, 0x78, 0xf7, 0x81, 0x30, 0x1c, 0x92, 0xa,
			0x12, 0xfa, 0x2a, 0x59, 0x56, 0x44, 0x47, 0x5,
			0xc0, 0xce, 0xd5, 0x3, 0x9e, 0x89, 0xed, 0x52,
			0x7a, 0xfa, 0x62, 0xc5, 0x8, 0x40, 0x67, 0xf2,
			0x50, 0x84, 0x5a, 0xf6, 0x54, 0xfa, 0x56, 0x28,
			0xc7, 0x5a, 0x58, 0xac, 0xe4, 0x1d, 0xcc, 0x17,
			0x4, 0x71, 0x6, 0x11, 0x5d, 0x37, 0xbb, 0xa2,
			0x67, 0xd8, 0xa7, 0x93, 0xde, 0x66, 0x93, 0x95,
			0x65, 0x84, 0x93, 0x2f, 0xa, 0xfb, 0x52, 0x71,
			0xf9, 0x7a, 0x89, 0xe4, 0x4f, 0x6f, 0x90, 0xac,
			0x1f, 0x48, 0xf0, 0xab, 0x65, 0xb3, 0xd0, 0xd9,
			0x6f, 0x18, 0xc7, 0x74, 0x24, 0xaf, 0x7d, 0xa5,
			0x24, 0xca, 0x82, 0x69, 0x2a, 0xb6, 0x26, 0xde,
			0x10, 0x78, 0x98, 0x20, 0xad, 0x14, 0x65, 0x10,
			0x12, 0xa7, 0x85, 0x6a, 0xe4, 0xd6, 0x28, 0x4f,
		},
	},
	{
		key: [KeyLen]byte{
			0xff, 0xe3, 0xb2, 0xff, 0x2d, 0x22, 0xbb, 0xd2,
			0xa2, 0xb4, 0x2f, 0xe, 0xca, 0x2e, 0x3b, 0xfd,
			0x46, 0xb9, 0x5e, 0x60, 0xfc, 0x62, 0x2e, 0xb5,
			0x57, 0x1c, 0xc4, 0xed, 0xe5, 0xc, 0x1c, 0x39,
			0xff, 0xe2, 0x2f, 0x1e, 0xa4, 0xe7, 0xa0, 0xb7,
			0x45, 0xbb, 0x97, 0xd7, 0x9f, 0x2, 0x93, 0x9b,
			0xae, 0x4b, 0xed, 0x83, 0xa1, 0xb0, 0xdd, 0x44,
			0x59, 0xd6, 0xa4, 0x6d, 0x2b, 0x3a, 0xae, 0x4c,
			0xa9, 0xce, 0x3f, 0x82, 0x12, 0x42, 0x8e, 0xe5,
			0x23, 0x71, 0x9d, 0x30, 0x6, 0x28, 0xb0, 0xf2,
			0xe4, 0xae, 0x8, 0x85, 0x41, 0xf4, 0xac, 0x18,
			0xac, 0xf6, 0x66, 0x1a, 0xc6, 0x42, 0x94, 0xa9,
			0x84, 0x43, 0xcb, 0xbd, 0x55, 0x16, 0xfa, 0xa,
			0x11, 0xa, 0x23, 0x2d, 0x26, 0xf0, 0x75, 0xc7,
			0xa4, 0xae, 0xa, 0xb8, 0x40, 0x61, 0x4a, 0xe2,
			0xaf, 0xf2, 0x27, 0x53, 0xb1, 0xd2, 0x68, 0x18,
			0xcf, 0x7e, 0x12, 0x8e, 0x41, 0x4f, 0x6f, 0x71,
			0x4, 0x58, 0x9b, 0x9d, 0x49, 0x41, 0xfa, 0xd4,
			0xe4, 0xe2, 0x3f, 0x8b, 0x19, 0x86, 0x3e, 0xfb,
			0xdf, 0x52, 0x59, 0x7e, 0x93, 0x6c, 0xf6, 0x97,
			0x1, 0x22, 0x8d, 0x4e, 0xdc, 0x6c, 0x9e, 0x9e,
			0x50, 0x23, 0x3b, 0x26, 0xcc, 0x62, 0xa2, 0x67,
			0x49, 0x4a, 0x2d, 0x72, 0xba, 0xdf, 0x1d, 0xf1,
			0xfc, 0x11, 0xba, 0xd8, 0x9b, 0xa, 0x93, 0x2b,
			0xd8, 0xf4, 0x5b, 0x8e, 0xf2, 0x26, 0xca, 0xf0,
			0x78, 0x49, 0xbf, 0x4e, 0xaa, 0x74, 0xea, 0xa3,
		},
		block: []byte{
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
			0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
			0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
			0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
			0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
			0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
			0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
			0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
			0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
			0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
			0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
			0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
			0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
			0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
			0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
			0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
		},
		want: []byte{
			0x50, 0x88, 0xba, 0x34, 0x51, 0xa9, 0x5c, 0xf1,
			0x4, 0x9, 0x80, 0x7, 0xf3, 0x0, 0x22, 0x68,
			0x48, 0xab, 0xc7, 0xa0, 0xc0, 0x24, 0xe7, 0xbe,
			0x6, 0x86, 0x6e, 0xf6, 0xd6, 0x2b, 0xf0, 0xa2,
			0x85, 0xb8, 0x26, 0xcb, 0x97, 0xcf, 0x86, 0x28,
			0x9, 0x8a, 0xe7, 0xfa, 0x9, 0x39, 0xee, 0xf,
			0x99, 0xad, 0x53, 0xca, 0xf9, 0x2e, 0xf, 0x58,
			0xf4, 0x3f, 0x9e, 0xd3, 0x1e, 0x7e, 0xcf, 0x87,
			0x18, 0xfa, 0x20, 0xe3, 0x8c, 0xe0, 0xe5, 0xd6,
			0x7c, 0x1b, 0x85, 0x31, 0x77, 0x1a, 0xca, 0x85,
			0x6a, 0xe5, 0xb9, 0xf1, 0x7, 0x59, 0x77, 0xbd,
			0xc7, 0xf0, 0x33, 0xd1, 0x1, 0x9e, 0x4e, 0x66,
			0x92, 0xb8, 0x46, 0x3, 0x1d, 0x72, 0x7e, 0xc6,
			0xa1, 0x2d, 0x24, 0x2e, 0x7f, 0xdc, 0x13, 0xc5,
			0x4d, 0x33, 0xf6, 0x92, 0xfa, 0x4d, 0x3, 0x85,
			0x1, 0xa4, 0xd1, 0x21, 0x5f, 0x4f, 0x8c, 0xf0,
		},
	},
}

func TestLionessVectors(t *testing.T) {
	for i, v := range draftTestVectors {
		cipher := NewCipher(v.key, len(v.block))
		ciphertext, err := cipher.Encrypt(v.block)
		if err != nil {
			t.Errorf("[%d]: encryption failed: %s", i, err)
			continue
		}
		if !bytes.Equal(ciphertext, v.want) {
			t.Errorf("ciphertext mismatch for test vector %d", i)
			t.Fail()
		}
	}
}

var result []byte

func BenchmarkLioness(b *testing.B) {
	var key [KeyLen]byte
	for i := 0; i < KeyLen; i++ {
		key[i] = byte(i) & 0xff
	}

	plaintext := []byte("Open, secure and reliable connectivity is necessary (although not   sufficient) to excercise the human rights such as freedom of   expression and freedom of association [FOC], as defined in the   Universal Declaration of Human Rights [UDHR].  The purpose of the   Internet to be a global network of networks that provides unfettered   connectivity to all users and for any content [RFC1958].  This   objective of stimulating global connectivity contributes to the   Internet's role as an enabler of human rights.  Next to that, the   strong commitment to security [RFC1984] [RFC3365] and privacy   [RFC6973] [RFC7258] in the Internet's architectural design contribute   to the strengthening of the Internet as a human rights enabling   environment.  One could even argue that the Internet is not only an   enabler of human rights, but that human rights lie at the basis of,   and are ingrained in, the architecture of the network.  Internet   connectivity increases the capacity for individuals to exercise their   rights, the core of the Internet, its architectural design is   therefore closely intertwined with the human rights framework   [CathFloridi].  The quintessential link between the Internet's   architecture and human rights has been argued by many.  [Bless] for   instance argues that, 'to a certain extent, the Internet and its   protocols have already facilitated the realization of human rights,   e.g., the freedom of assembly and expression.  In contrast, measures   of censorship and pervasive surveillance violate fundamental human   rights.'  [Denardis15] argues that 'Since the first hints of Internet   commercialization and internationalization,")
	cipher := NewCipher(key, len(plaintext)) // key and block-size

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
