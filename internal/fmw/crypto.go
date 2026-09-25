// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"strconv"
	"sync"
)

// Encryption of format v1 (section 7): each encrypted file is the OpenSSL
// "enc" format ("Salted__", an 8-byte salt, AES-256-CBC with PKCS#7
// padding). PBKDF2-HMAC-SHA256 over the password and the salt gives 80
// bytes: AES key (0-31), IV (32-47) and HMAC key (48-79). The HMAC-SHA256
// of the whole stored file authenticates it (encrypt-then-MAC).
const (
	Magic     = "Salted__"
	HeaderLen = 16
	blockSize = aes.BlockSize
	// MinIterations and MaxIterations bound what an archive may ask for,
	// so a crafted fmw.json cannot make key derivation trivial or endless.
	MinIterations = 10000
	MaxIterations = 10000000
)

// Keys are the keys of one encrypted file.
type Keys struct {
	AES []byte
	IV  []byte
	MAC []byte
}

var (
	keyCache   = map[string]Keys{}
	keyCacheMu sync.Mutex
)

// DeriveKeys runs PBKDF2 for one salt (cached: each derivation takes a noticeable fraction of a second).
func DeriveKeys(password string, salt []byte, iterations int) (Keys, error) {
	if iterations < MinIterations || iterations > MaxIterations {
		return Keys{}, &FormatError{Msg: "unreasonable key derivation settings in fmw.json"}
	}
	id := sha256.Sum256([]byte(strconv.Itoa(iterations) + "\x00" + string(salt) + "\x00" + password))
	keyCacheMu.Lock()
	k, ok := keyCache[string(id[:])]
	keyCacheMu.Unlock()
	if ok {
		return k, nil
	}
	b, err := pbkdf2.Key(sha256.New, password, salt, iterations, 80)
	if err != nil {
		return Keys{}, err
	}
	k = Keys{AES: b[0:32], IV: b[32:48], MAC: b[48:80]}
	keyCacheMu.Lock()
	if len(keyCache) >= 1<<16 { // Room for every part of any real backup.
		keyCache = map[string]Keys{}
	}
	keyCache[string(id[:])] = k
	keyCacheMu.Unlock()
	return k, nil
}

// SaltOf returns the salt from the first 16 bytes of an encrypted file.
func SaltOf(header []byte) ([]byte, error) {
	if len(header) != HeaderLen || string(header[:8]) != Magic {
		return nil, &FormatError{Msg: `not an encrypted FMW file (missing "Salted__" header)`}
	}
	return append([]byte(nil), header[8:16]...), nil
}

// NewMAC starts the HMAC of a stored encrypted file.
func NewMAC(k Keys) hash.Hash { return hmac.New(sha256.New, k.MAC) }

// ErrBadPadding means the ciphertext does not end in valid PKCS#7 padding.
var ErrBadPadding = errors.New("the encrypted data is damaged (bad padding or length)")

// DecryptReader decrypts AES-256-CBC ciphertext (after the 16-byte header)
// as a stream, removing the PKCS#7 padding at the end.
type DecryptReader struct {
	src     io.Reader
	mode    cipher.BlockMode
	pending []byte // Ciphertext not yet decrypted; the last block is held back until EOF.
	out     []byte // Plain text ready to return.
	buf     []byte
	done    bool
	err     error
}

// NewDecryptReader wraps the ciphertext that follows the "Salted__" header.
func NewDecryptReader(src io.Reader, k Keys) (*DecryptReader, error) {
	block, err := aes.NewCipher(k.AES)
	if err != nil {
		return nil, err
	}
	return &DecryptReader{src: src, mode: cipher.NewCBCDecrypter(block, k.IV), buf: make([]byte, 256*1024)}, nil
}

// Read implements io.Reader.
func (d *DecryptReader) Read(p []byte) (int, error) {
	for len(d.out) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		n, err := d.src.Read(d.buf)
		d.pending = append(d.pending, d.buf[:n]...)
		switch {
		case errors.Is(err, io.EOF):
			d.done = true
			if len(d.pending) == 0 || len(d.pending)%blockSize != 0 {
				d.err = ErrBadPadding
				return 0, d.err
			}
			plain := make([]byte, len(d.pending))
			d.mode.CryptBlocks(plain, d.pending)
			d.pending = nil
			pad := int(plain[len(plain)-1])
			if pad < 1 || pad > blockSize || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
				d.err = ErrBadPadding
				return 0, d.err
			}
			d.out = plain[:len(plain)-pad]
		case err != nil:
			d.err = err
			return 0, err
		default:
			whole := len(d.pending) / blockSize * blockSize
			if whole == len(d.pending) {
				whole -= blockSize // Keep the last block: it may carry the padding.
			}
			if whole > 0 {
				plain := make([]byte, whole)
				d.mode.CryptBlocks(plain, d.pending[:whole])
				d.pending = append(d.pending[:0], d.pending[whole:]...)
				d.out = plain
			}
		}
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}

// DecryptSmall checks the HMAC of a small encrypted file, then decrypts it.
func DecryptSmall(data []byte, password string, iterations int, wantMAC []byte) ([]byte, error) {
	if len(data) < HeaderLen {
		return nil, ErrWrongPassword
	}
	salt, err := SaltOf(data[:HeaderLen])
	if err != nil {
		return nil, err
	}
	k, err := DeriveKeys(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	m := NewMAC(k)
	m.Write(data)
	if !hmac.Equal(m.Sum(nil), wantMAC) {
		return nil, ErrWrongPassword
	}
	r, err := NewDecryptReader(bytes.NewReader(data[HeaderLen:]), k)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
