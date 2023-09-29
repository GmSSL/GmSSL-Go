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

func TestZuc(t *testing.T) {

	key, _ := RandBytes(ZucKeySize)
	iv, _ := RandBytes(ZucIvSize)
	plaintext, _ := RandBytes(20)

	zuc, _ := NewZuc(key, iv)
	ciphertext, _ := zuc.Update(plaintext)
	ciphertext_last, _ := zuc.Finish()
	ciphertext = append(ciphertext, ciphertext_last...)

	zuc, _ = NewZuc(key, iv)
	decrypted, _ := zuc.Update(ciphertext)
	decrypted_last, _ := zuc.Finish()
	decrypted = append(decrypted, decrypted_last...)

	if bytes.Equal(decrypted, plaintext) != true {
		t.Error("Test failure")
	}
}

