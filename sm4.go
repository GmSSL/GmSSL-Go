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
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	Sm4KeySize = 16
	Sm4BlockSize = 16

	Sm4CbcIvSize = 16

	Sm4CtrIvSize = 16

	Sm4GcmMinIvSize = 8
	Sm4GcmMaxIvSize = 64
	Sm4GcmDefaultIvSize = 64
	Sm4GcmDefaultTagSize = 16
	Sm4GcmMaxTagSize = 16
)


type Sm4 struct {
	sm4_key C.SM4_KEY
	encrypt bool
}

func NewSm4(key []byte, encrypt bool) (*Sm4, error) {

	if key == nil {
		return nil, errors.New("No key")
	}

	if len(key) != Sm4KeySize {
		return nil, errors.New("Invalid key length")
	}

	sm4 := new(Sm4)

	if encrypt == true {
		C.sm4_set_encrypt_key(&sm4.sm4_key, (*C.uchar)(&key[0]))
	} else {
		C.sm4_set_decrypt_key(&sm4.sm4_key, (*C.uchar)(&key[0]))
	}
	sm4.encrypt = encrypt

	return sm4, nil
}

func (sm4 *Sm4) Encrypt(block []byte) ([]byte, error) {
	if len(block) != Sm4BlockSize {
		return nil, errors.New("Invalid block size")
	}
	outbuf := make([]byte, Sm4BlockSize)
	C.sm4_encrypt(&sm4.sm4_key, (*C.uchar)(&block[0]), (*C.uchar)(unsafe.Pointer(&outbuf[0])))
	return outbuf, nil
}



type Sm4Cbc struct {
	sm4_cbc_ctx C.SM4_CBC_CTX
	encrypt bool
}

func NewSm4Cbc(key []byte, iv []byte, encrypt bool) (*Sm4Cbc, error) {

	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) != Sm4CbcIvSize {
		return nil, errors.New("Invalid IV length")
	}

	sm4_cbc := new(Sm4Cbc)

	if encrypt == true {
		if 1 != C.sm4_cbc_encrypt_init(&sm4_cbc.sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_init(&sm4_cbc.sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	sm4_cbc.encrypt = encrypt

	return sm4_cbc, nil
}

func (cbc *Sm4Cbc) Reset(key []byte, iv []byte, encrypt bool) error {

	if key == nil {
		return errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return errors.New("Invalid key length")
	}
	if len(iv) != Sm4CbcIvSize {
		return errors.New("Invalid IV length")
	}

	if encrypt == true {
		if 1 != C.sm4_cbc_encrypt_init(&cbc.sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_init(&cbc.sm4_cbc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
			return errors.New("Libgmssl inner error")
		}
	}
	cbc.encrypt = encrypt

	return nil
}

func (cbc *Sm4Cbc) Update(data []byte) ([]byte, error) {

	outbuf := make([]byte, len(data) + Sm4BlockSize)
	var outlen C.size_t

	if cbc.encrypt {
		if 1 != C.sm4_cbc_encrypt_update(&cbc.sm4_cbc_ctx,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
			(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_update(&cbc.sm4_cbc_ctx,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
			(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}

	return outbuf[:outlen], nil
}

func (cbc *Sm4Cbc) Finish() ([]byte, error) {

	outbuf := make([]byte, Sm4BlockSize)
	var outlen C.size_t

	if cbc.encrypt {
		if 1 != C.sm4_cbc_encrypt_finish(&cbc.sm4_cbc_ctx,
			(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_cbc_decrypt_finish(&cbc.sm4_cbc_ctx,
			(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}

	return outbuf[:outlen], nil
}


type Sm4Ctr struct {
	sm4_ctr_ctx C.SM4_CTR_CTX
}

func NewSm4Ctr(key []byte, iv []byte) (*Sm4Ctr, error) {

	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) != Sm4CtrIvSize {
		return nil, errors.New("Invalid IV length")
	}

	ctr := new(Sm4Ctr)

	if 1 != C.sm4_ctr_encrypt_init(&ctr.sm4_ctr_ctx,
		(*C.uchar)(unsafe.Pointer(&key[0])), (*C.uchar)(unsafe.Pointer(&iv[0]))) {
		return nil, errors.New("Libgmssl inner error")
	}

	return ctr, nil
}

func (ctr *Sm4Ctr) Reset(key []byte, iv []byte) error {

	if key == nil {
		return errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return errors.New("Invalid key length")
	}
	if len(iv) != Sm4CtrIvSize {
		return errors.New("Invalid IV length")
	}

	if 1 != C.sm4_ctr_encrypt_init(&ctr.sm4_ctr_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
		return errors.New("Libgmssl inner error")
	}

	return nil
}

func (ctr *Sm4Ctr) Update(data []byte) ([]byte, error) {

	outbuf := make([]byte, len(data) + Sm4BlockSize)
	var outlen C.size_t

	if 1 != C.sm4_ctr_encrypt_update(&ctr.sm4_ctr_ctx,
		(*C.uchar)(&data[0]), C.size_t(len(data)), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}

	return outbuf[:outlen], nil
}

func (ctr *Sm4Ctr) Finish() ([]byte, error) {
	outbuf := make([]byte, Sm4BlockSize)
	var outlen C.size_t

	if 1 != C.sm4_ctr_encrypt_finish(&ctr.sm4_ctr_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}


type Sm4Gcm struct {
	sm4_gcm_ctx C.SM4_GCM_CTX
	encrypt bool
}

func NewSm4Gcm(key []byte, iv []byte, aad []byte, taglen int, encrypt bool) (*Sm4Gcm, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) < Sm4GcmMinIvSize || len(iv) > Sm4GcmMaxIvSize {
		return nil, errors.New("Invalid IV length")
	}
	if taglen > Sm4GcmMaxTagSize {
		return nil, errors.New("Invalid Tag length")
	}

	gcm := new(Sm4Gcm)

	if encrypt == true {
		if 1 != C.sm4_gcm_encrypt_init(&gcm.sm4_gcm_ctx,
			(*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_init(&gcm.sm4_gcm_ctx, (*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	gcm.encrypt = encrypt

	return gcm, nil
}

func (gcm *Sm4Gcm) Reset(key []byte, iv []byte, aad []byte, taglen int, encrypt bool) error {
	if key == nil {
		errors.New("No key")
	}
	if len(key) != Sm4KeySize {
		return errors.New("Invalid key length")
	}
	if len(iv) < Sm4GcmMinIvSize || len(iv) > Sm4GcmMaxIvSize {
		return errors.New("Invalid IV length")
	}
	if taglen > Sm4GcmMaxTagSize {
		return errors.New("Invalid Tag length")
	}

	if encrypt == true {
		if 1 != C.sm4_gcm_encrypt_init(&gcm.sm4_gcm_ctx,
			(*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_init(&gcm.sm4_gcm_ctx, (*C.uchar)(&key[0]), C.size_t(len(key)), (*C.uchar)(&iv[0]), C.size_t(len(iv)),
			(*C.uchar)(&aad[0]), C.size_t(len(aad)), C.size_t(taglen)) {
			return errors.New("Libgmssl inner error")
		}
	}
	gcm.encrypt = encrypt

	return nil
}

func (gcm *Sm4Gcm) Update(data []byte) ([]byte, error) {
	outbuf := make([]byte, len(data) + Sm4BlockSize)
	var outlen C.size_t
	if gcm.encrypt {
		if 1 != C.sm4_gcm_encrypt_update(&gcm.sm4_gcm_ctx,
			(*C.uchar)(&data[0]), C.size_t(len(data)), (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if 1 != C.sm4_gcm_decrypt_update(&gcm.sm4_gcm_ctx,
			(*C.uchar)(&data[0]), C.size_t(len(data)), (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}

func (gcm *Sm4Gcm) Finish() ([]byte, error) {
	var outbuf []byte
	var outlen C.size_t
	if gcm.encrypt {
		outbuf = make([]byte, Sm4BlockSize + Sm4GcmMaxTagSize)
		if 1 != C.sm4_gcm_encrypt_finish(&gcm.sm4_gcm_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		outbuf = make([]byte, Sm4BlockSize)
		if 1 != C.sm4_gcm_decrypt_finish(&gcm.sm4_gcm_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	return outbuf[:outlen], nil
}

