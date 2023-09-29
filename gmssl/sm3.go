/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/* +build cgo */

package gmssl

/*
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/error.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	Sm3DigestSize = 32

	Sm3HmacMinKeySize = 16
	Sm3HmacMaxKeySize = 64
	Sm3HmacSize = 32

	Sm3Pbkdf2MinIter = 10000
	Sm3Pbkdf2MaxIter = 16777216
	Sm3Pbkdf2MaxSaltSize = 64
	Sm3Pbkdf2DefaultSaltSize = 8
	Sm3Pbkdf2MaxKeySize = 256
)


type Sm3 struct {
	sm3_ctx C.SM3_CTX
}

func NewSm3() *Sm3 {
	sm3 := new(Sm3)
	C.sm3_init(&sm3.sm3_ctx)
	return sm3
}

func (sm3 *Sm3) Update(data []byte) {
	if len(data) > 0 {
		C.sm3_update(&sm3.sm3_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)));
	}
}

func (sm3 *Sm3) Digest() []byte {
	dgst := make([]byte, Sm3DigestSize)
	C.sm3_finish(&sm3.sm3_ctx, (*C.uchar)(unsafe.Pointer(&dgst[0])))
	return dgst
}

func (sm3 *Sm3) Reset() {
	C.sm3_init(&sm3.sm3_ctx)
}


type Sm3Hmac struct {
	sm3_hmac_ctx C.SM3_HMAC_CTX
}

func NewSm3Hmac(key []byte) (*Sm3Hmac, error) {
	if len(key) < Sm3HmacMinKeySize || len(key) > Sm3HmacMaxKeySize {
		return nil, errors.New("Invalid key length")
	}
	hmac := new(Sm3Hmac)
	C.sm3_hmac_init(&hmac.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	return hmac, nil
}

func (hmac *Sm3Hmac) Update(data []byte) {
	if len(data) > 0 {
		C.sm3_hmac_update(&hmac.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
}

func (hmac *Sm3Hmac) GenerateMac() []byte {
	mac := make([]byte, Sm3HmacSize)
	C.sm3_hmac_finish(&hmac.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&mac[0])))
	return mac
}

func (hmac *Sm3Hmac) Reset(key []byte) error {
	if len(key) < Sm3HmacMinKeySize || len(key) > Sm3HmacMaxKeySize {
		return errors.New("Invalid key length")
	}
	C.sm3_hmac_init(&hmac.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	return nil
}


func Sm3Pbkdf2(pass string, salt []byte, iter uint, keylen uint) ([]byte, error) {

	if len(salt) > Sm3Pbkdf2MaxSaltSize {
		return nil, errors.New("Invalid salt size")
	}

	if iter < Sm3Pbkdf2MinIter || iter > Sm3Pbkdf2MaxIter {
		return nil, errors.New("Invalid iter value")
	}

	if keylen > Sm3Pbkdf2MaxKeySize {
		return nil, errors.New("Invalid key length")
	}

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	key := make([]byte, keylen)

	C.pbkdf2_hmac_sm3_genkey(pass_str, C.strlen(pass_str),
		(*C.uchar)(unsafe.Pointer(&salt[0])), C.size_t(len(salt)),
		C.size_t(iter), C.size_t(keylen),
		(*C.uchar)(unsafe.Pointer(&key[0])))

	return key, nil
}

