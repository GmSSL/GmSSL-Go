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
	"bytes"
	"testing"
)

func TestSm2(t *testing.T) {

	sm2, _ := GenerateSm2Key()
	sm2.ExportEncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2.ExportPublicKeyInfoPem("sm2pub.pem")

	sm2pri, _ := ImportSm2EncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2pub, _ := ImportSm2PublicKeyInfoPem("sm2pub.pem")

	z, _ := sm2pub.ComputeZ(Sm2DefaultId)
	if len(z) != 32 {
		t.Error("Test failure")
	}

	dgst, _ := RandBytes(Sm3DigestSize)
	signature, _ := sm2pri.Sign(dgst)
	ret := sm2pub.Verify(dgst, signature)
	if ret != true {
		t.Error("Test failure")
	}

	plaintext, _ := RandBytes(Sm2MaxPlaintextSize/4)
	ciphertext, _ := sm2pub.Encrypt(plaintext)
	decrypted, _ := sm2pri.Decrypt(ciphertext)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

func TestSm2Sign(t *testing.T) {

	sm2, _ := GenerateSm2Key()
	sm2.ExportEncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2.ExportPublicKeyInfoPem("sm2pub.pem")

	sm2pri, _ := ImportSm2EncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2pub, _ := ImportSm2PublicKeyInfoPem("sm2pub.pem")

	sign, _ := NewSm2Signature(sm2pri, Sm2DefaultId, true)
	sign.Update([]byte("abc"))
	signature, _ := sign.Sign()

	sign, _ = NewSm2Signature(sm2pub, Sm2DefaultId, false)
	sign.Update([]byte("abc"))
	ret := sign.Verify(signature)

	if ret != true {
		t.Error("Test failure")
	}
}






