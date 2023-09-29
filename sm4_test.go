/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package gmssl

import (
	"encoding/hex"
	"bytes"
	"testing"
)

func TestSm4(t *testing.T) {

	key := []byte("1234567812345678")
	plaintext := []byte("block of message")
	ciphertext_hex := "dd99d30fd7baf5af2930335d2554ddb7"

	sm4, _ := NewSm4(key, true)
	ciphertext, _ := sm4.Encrypt(plaintext)
	if hex.EncodeToString(ciphertext) != ciphertext_hex {
		t.Error("Test failure")
	}

	sm4, _ = NewSm4(key, false)
	decrypted, _ := sm4.Encrypt(ciphertext)
	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

func TestSm4Cbc(t *testing.T) {

	key, _ := RandBytes(Sm4KeySize)
	iv, _ := RandBytes(Sm4CbcIvSize)
	plaintext, _ := RandBytes(20)

	sm4_cbc, _ := NewSm4Cbc(key, iv, true)
	ciphertext, _ := sm4_cbc.Update(plaintext)
	ciphertext_last, _ := sm4_cbc.Finish()
	ciphertext = append(ciphertext, ciphertext_last...)

	sm4_cbc, _ = NewSm4Cbc(key, iv, false)
	decrypted, _ := sm4_cbc.Update(ciphertext)
	decrypted_last, _ := sm4_cbc.Finish()
	decrypted = append(decrypted, decrypted_last...)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

func TestSm4Ctr(t *testing.T) {

	key, _ := RandBytes(Sm4KeySize)
	iv, _ := RandBytes(Sm4CtrIvSize)
	plaintext, _ := RandBytes(20)

	sm4_ctr, _ := NewSm4Ctr(key, iv)
	ciphertext, _ := sm4_ctr.Update(plaintext)
	ciphertext_last, _ := sm4_ctr.Finish()
	ciphertext = append(ciphertext, ciphertext_last...)

	sm4_ctr, _ = NewSm4Ctr(key, iv)
	decrypted, _ := sm4_ctr.Update(ciphertext)
	decrypted_last, _ := sm4_ctr.Finish()
	decrypted = append(decrypted, decrypted_last...)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

func TestSm4Gcm(t *testing.T) {

	key, _ := RandBytes(Sm4KeySize)
	iv, _ := RandBytes(Sm4GcmDefaultIvSize)
	aad := []byte("Additional Authenticated-only Data")
	plaintext, _ := RandBytes(20)

	sm4_gcm, _ := NewSm4Gcm(key, iv, aad, Sm4GcmMaxTagSize, true)
	ciphertext, _ := sm4_gcm.Update(plaintext)
	ciphertext_last, _ := sm4_gcm.Finish()
	ciphertext = append(ciphertext, ciphertext_last...)

	sm4_gcm, _ = NewSm4Gcm(key, iv, aad, Sm4GcmMaxTagSize, false)
	decrypted, _ := sm4_gcm.Update(ciphertext)
	decrypted_last, _ := sm4_gcm.Finish()
	decrypted = append(decrypted, decrypted_last...)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}


