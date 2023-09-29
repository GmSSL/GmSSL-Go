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
#include <gmssl/zuc.h>
#include <gmssl/error.h>
*/
import "C"

import (
	"errors"
)

const ZucKeySize = 16
const ZucIvSize = 16


type Zuc struct {
	zuc_ctx C.ZUC_CTX
}

func NewZuc(key []byte, iv []byte) (*Zuc, error) {
	if key == nil {
		return nil, errors.New("No key")
	}
	if len(key) != int(C.ZUC_KEY_SIZE) {
		return nil, errors.New("Invalid key length")
	}
	if len(iv) != int(C.ZUC_IV_SIZE) {
		return nil, errors.New("Invalid IV length")
	}

	zuc := new(Zuc)

	if 1 != C.zuc_encrypt_init(&zuc.zuc_ctx, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0])) {
		return nil, errors.New("Libgmssl inner error")
	}
	return zuc, nil
}

func (zuc *Zuc) Update(in []byte) ([]byte, error) {
	outbuf := make([]byte, len(in) + 16)
	var outlen C.size_t
	if 1 != C.zuc_encrypt_update(&zuc.zuc_ctx, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (zuc *Zuc) Finish() ([]byte, error) {
	outbuf := make([]byte, 16)
	var outlen C.size_t
	if 1 != C.zuc_encrypt_finish(&zuc.zuc_ctx, (*C.uchar)(&outbuf[0]), &outlen) {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}
