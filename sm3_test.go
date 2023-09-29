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

func TestSm3Hmac(t *testing.T) {

	key := []byte("1234567812345678")
	mac_hex := "0a69401a75c5d471f5166465eec89e6a65198ae885c1fdc061556254d91c1080"

	hmac, _ := NewSm3Hmac(key)
	hmac.Update([]byte("abc"))
	mac := hmac.GenerateMac()

	if hex.EncodeToString(mac) != mac_hex {
		t.Error("Test failure")
	}
}

func TestSm3Pbkdf2(t *testing.T) {

	passwd := "password"
	salt := []byte("12345678")
	const iterator = 10000
	const keylen = 32
	key_hex := "ac5b4a93a130252181434970fa9d8e6f1083badecafc4409aaf0097c813e9fc6"

	key, _ := Sm3Pbkdf2(passwd, salt, iterator, keylen)

	if hex.EncodeToString(key) != key_hex {
		t.Error("Test failure")
	}

}

