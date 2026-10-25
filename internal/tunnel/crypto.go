package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
)

const aesBlockSize = 16

func encryptCBC(key, iv, plain []byte) []byte {
	pad := (aesBlockSize - len(plain)%aesBlockSize) % aesBlockSize
	in := make([]byte, len(plain)+pad)
	copy(in, plain)
	out := make([]byte, len(in))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, in)
	return out
}

func decryptCBC(key, iv, ct []byte) []byte {
	if len(ct) == 0 || len(ct)%aesBlockSize != 0 {
		return nil
	}
	out := make([]byte, len(ct))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return out
}
