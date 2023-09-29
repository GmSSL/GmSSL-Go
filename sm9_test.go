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

func TestSm9Enc(t *testing.T) {

	master, _ := GenerateSm9EncMasterKey()
	master.ExportEncryptedMasterKeyInfoPem("sm9enc.pem", "password")
	master.ExportMasterPublicKeyPem("sm9encpub.pem")

	master, _ = ImportEncryptedSm9EncMasterKeyInfoPem("sm9enc.pem", "password")
	master_pub, _ := ImportSm9EncMasterPublicKeyPem("sm9encpub.pem")

	id := "Alice"
	key, _ := master.ExtractKey(id)
	key.ExportEncryptedPrivateKeyInfoPem("sm9encpri.pem", "password")
	key, _ = ImportEncryptedSm9EncPrivateKeyInfoPem("sm9encpri.pem", "password", id)

	plaintext := []byte("plaintext")
	ciphertext, _ := master_pub.Encrypt(plaintext, id)
	decrypted, _ := key.Decrypt(ciphertext)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

func TestSm9Sign(t *testing.T) {

	master, _ := GenerateSm9SignMasterKey()
	master.ExportEncryptedMasterKeyInfoPem("sm9sign.pem", "password")
	master.ExportMasterPublicKeyPem("sm9signpub.pem")

	master, _ = ImportEncryptedSm9SignMasterKeyInfoPem("sm9sign.pem", "password")
	master_pub, _ := ImportSm9SignMasterPublicKeyPem("sm9signpub.pem")

	id := "Alice"
	key, _ := master.ExtractKey(id)
	key.ExportEncryptedPrivateKeyInfoPem("sm9signpri.pem", "password")
	key, _ = ImportEncryptedSm9SignPrivateKeyInfoPem("sm9signpri.pem", "password", id)

	sign, _ := NewSm9Signature(true)
	sign.Update([]byte("abc"))
	signature, _ := sign.Sign(key)

	sign, _ = NewSm9Signature(false)
	sign.Update([]byte("abc"))
	ret := sign.Verify(signature, master_pub, id)

	if ret != true {
		t.Error("Test failure")
	}
}



