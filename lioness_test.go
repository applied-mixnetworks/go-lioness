package lioness

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLionessBlockSizeError(t *testing.T) {
	var key [KeyLen]byte
	for i := 0; i < KeyLen; i++ {
		key[i] = byte(i) & 0xff
	}
	_, err := NewCipher(key, 15)
	if err == nil {
		t.Error("expected block size mismatch error")
		t.Fail()
	}
	cipher, err := NewCipher(key, 1024)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	plaintext := []byte("quick brown fox")
	_, err = cipher.Encrypt(plaintext)
	if err == nil {
		t.Error("expected block size mismatch error")
		t.Fail()
	}
	_, err = cipher.Decrypt(plaintext)
	if err == nil {
		t.Error("expected block size mismatch error")
		t.Fail()
	}
}

func TestBasicLionessEncrypt(t *testing.T) {
	var err error
	var key [KeyLen]byte
	for i := 0; i < KeyLen; i++ {
		key[i] = byte(i) & 0xff
	}

	plaintext := []byte("'What do we know,' he had said, 'of the world and the universe about us? Our means of receiving impressions are absurdly few, and our notions of surrounding objects infinitely narrow. We see things only as we are constructed to see them, and can gain no idea of their absolute nature. With five feeble senses we pretend to comprehend the boundlessly complex cosmos, yet other beings with wider, stronger, or different range of senses might not only see very differently the things we see, but might see and st")
	cipher, err := NewCipher(key, len(plaintext)) // key and block-size
	if err != nil {
		t.Error(err)
		t.Fail()
	}
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
	key   string
	block string
	want  string
}{
	{
		key: "0f2c69732932c99e56fa50fbb2763ad77ee221fc5d9e6c08f89fc577a7467f1ee34" +
			"003440ee2bfbfaac60912b0e547fbe9a6a9292db70bc718c6f2773ab198ac8f25537" +
			"8f7ea799e1d4b8596079173b6e443c416f13195f1976acc03d53a4b8581b609df3b7" +
			"029d5b487051d5ae4189129c045edc8822e1f52e30251e4b322b3f6d6e8bb0ddb057" +
			"8dcba41603abf5e51848c84d2082d293f30a645faf4df028ee2c40853ea33e40b55f" +
			"ca902371dc00dc1e0e77161bd097a59e8368bf99174d9",
		block: "5ac4cb9674a8908915a2b1aaf2043271612531911a26186bd5c811951330753a0e3259f3fcf52f" +
			"b86e666ab4d96243e57d73b976611f928d44ad137799016861576ca0a6b8a8a9e2ea02db71e71c" +
			"9654e476ca845c44456eba62f11f004b222756e485185c446c30b7a05cf9acd53b3131227b428d" +
			"a5c9601664d45ae5c2387956307961a0680894844190605dce0c86e597105884e151eb8a005eda" +
			"08ff5891a6b40bae299cddad979063a9a356f3477feabb9cc7bd80a1e2d6a419fcd8af9e98f7b1" +
			"93c71bd6056d7634b8c2b8f85920f314554104659e52d9266ddbc2ac40c1b875f6b00225f832cf" +
			"310e139ad8cc2568608f0323534fa15a84280e776e7e1167a001f6e18c49f3cd02c19837da47ac" +
			"091219ee2fdb4458836db20cbd362bb65add9b40f2817f666caf19787abc2013737eea8c7552d7" +
			"55a29beba5da31956f75fe7628221fe8d0a75da5bee39af956a2246c5a339560dcf029eb76d191" +
			"963354b70142df29ec69930977ce2f0e491513664ce83a8fa75f3e698530cf9dafbdb90b19745e" +
			"9257d03d7320c6d306f529eda242cb3f6f452a943f6e1c04eb02cbb0368d79e49a2b42ac3ff7cd" +
			"9a5686bfdb90a29322016bbcef5c733f451a9f4ea7c534116158eb611796d47b83ffe7cd6e6c11" +
			"d56e2d26c7a386853212a2f92efeabc74e8fe69e3d374d7b033d0ec9862221435b14ad534217ad" +
			"7da50bc236",
		want: "9eb45ca2ca4d0b6ff05a749511aad1357aa64caf9ce547c7388fe24fd1300fe856bb5c396869a" +
			"cd21c45805e6a7c8a1b7f71cc5f0ea9dd0c4ecd4bba9a7a4853bc352bc9f6562e9907973f91fb" +
			"cf7c710f5a89abc8eb4489b90e8111cbf85ffd595d603268ddceb40e39e747a4e7bd5c965585b" +
			"6964e180bd6ccb9d0fad210c7f7dd6f90cf6db9bda70d41d3922cedec5ea147ef318de5f34e6f" +
			"e5bd646859a9d4171b973b6b58c8d7f94bc9eb293c197f3408a51e3626196e3f6bca625cef90f" +
			"a7a3e3713bdaebdda82f48db1a97c9ed5c48bc419dbc3d1f9ef43d1b17dd83c966bde9d9360b7" +
			"cdac0871844c27921dcf3bb7edce9fb24661a41a8f92c8502925f062e9cd2f77c561e5825eae2" +
			"11657652330bc64cd63b18d1014975f167f8b68d6e702dd3d3547971662238216cc5b07517cc9" +
			"0aaa49a61ee423861cdc49c0e1f64e086007095a00f8adb0314fd85c88158001202edf2ed43c2" +
			"01176d6141e469dd89430352a927ee22a41c62c8cfdfd5d592e76793e58a9c63b7fe6dad335d7" +
			"acec90727675854d7708358115794e013bb4fdb504c44e21ce500f764fac211e8de20b81ca55f" +
			"c778ace024d2a40045241e71b023ceb519c8c28285c333b9f90f5e2cde21ca6744e43f89d0054" +
			"5dd34df072c7214f6cbd2123c4b0613614609961dd855d6d611c3018e4df3550b4e93f33f7c3e" +
			"8b2c890ca0405c957aa277d",
	},
}

func TestLionessVectors(t *testing.T) {
	for i, v := range draftTestVectors {
		block, err := hex.DecodeString(v.block)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		var cipherKey [KeyLen]byte
		copy(cipherKey[:], key)
		cipher, err := NewCipher(cipherKey, len(block))
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		ciphertext, err := cipher.Encrypt(block)
		if err != nil {
			t.Errorf("[%d]: encryption failed: %s", i, err)
			t.Fail()
		}
		want, err := hex.DecodeString(v.want)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		if !bytes.Equal(ciphertext, want) {
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
	cipher, err := NewCipher(key, len(plaintext)) // key and block-size
	if err != nil {
		b.Fatal()
	}

	var ciphertext []byte
	for i := 0; i < b.N; i++ {
		ciphertext, err = cipher.Encrypt(plaintext)
		b.StopTimer()
		if err != nil {
			b.Fatal()
		}
		b.StartTimer()
	}

	// always store the result to a package level variable
	// so the compiler cannot eliminate the Benchmark itself.
	result = ciphertext
}
