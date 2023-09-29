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
	"testing"
)

func TestSm3(t *testing.T) {

	dgst_hex := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	sm3 := NewSm3()
	sm3.Update([]byte("abc"))
	dgst := sm3.Digest()

	if hex.EncodeToString(dgst) != dgst_hex {
		t.Error("Test failure")
	}
}

