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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
*/
import "C"

import (
	"unsafe"
	"errors"
)


const (
	Sm2DefaultId = "1234567812345678"
	Sm2MaxSignatureSize = 72
	Sm2MinPlaintextSize = 1
	Sm2MaxPlaintextSize = 255
	Sm2MinCiphertextSize = 45
	Sm2MaxCiphertextSize = 366
)


type Sm2Key struct {
	sm2_key C.SM2_KEY
	has_private_key bool
}

func GenerateSm2Key() (*Sm2Key, error) {
	ret := new(Sm2Key)

	if C.sm2_key_generate(&ret.sm2_key) != 1{
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportSm2EncryptedPrivateKeyInfoPem(pass string, path string) (*Sm2Key, error) {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm2Key)

	if C.sm2_private_key_info_decrypt_from_pem(&ret.sm2_key, pass_str, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportSm2PublicKeyInfoPem(path string) (*Sm2Key, error) {

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm2Key)

	if C.sm2_public_key_info_from_pem(&ret.sm2_key, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = false

	return ret, nil
}

func (sm2 *Sm2Key) ExportEncryptedPrivateKeyInfoPem(pass string, path string) error {

	if sm2.has_private_key != true {
		return errors.New("Not private key")
	}

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm2_private_key_info_encrypt_to_pem(&sm2.sm2_key, pass_str, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm2 *Sm2Key) ExportPublicKeyInfoPem(path string) error {
	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm2_public_key_info_to_pem(&sm2.sm2_key, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm2 *Sm2Key) ComputeZ(id string) ([]byte, error) {
	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))

	z := make([]byte, C.SM3_DIGEST_SIZE)

	if C.sm2_compute_z((*C.uchar)(&z[0]), &(sm2.sm2_key.public_key), id_str, C.strlen(id_str)) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return z, nil
}

func (sm2 *Sm2Key) Sign(dgst []byte) ([]byte, error) {
	if sm2.has_private_key != true {
		return nil, errors.New("Not private key")
	}
	sig := make([]byte, C.SM2_MAX_SIGNATURE_SIZE)
	var siglen C.size_t

	if C.sm2_sign(&sm2.sm2_key, (*C.uchar)(&dgst[0]), (*C.uchar)(&sig[0]), &siglen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return sig[:siglen], nil
}

func (sm2 *Sm2Key) Verify(dgst []byte, signature []byte) bool {
	if len(dgst) != C.SM3_DIGEST_SIZE {
		return false
	}
	if 1 != C.sm2_verify(&sm2.sm2_key, (*C.uchar)(&dgst[0]), (*C.uchar)(&signature[0]), C.size_t(len(signature))) {
		return false
	}
	return true
}

func (sm2 *Sm2Key) Encrypt(in []byte) ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_CIPHERTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_encrypt(&sm2.sm2_key, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (sm2 *Sm2Key) Decrypt(in []byte) ([]byte, error) {
	if sm2.has_private_key != true {
		return nil, errors.New("Not private key")
	}
	outbuf := make([]byte, C.SM2_MAX_PLAINTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_decrypt(&sm2.sm2_key, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}


type Sm2Signature struct {
	sm2_sign_ctx C.SM2_SIGN_CTX
	sign bool
}

func NewSm2Signature(sm2 *Sm2Key, id string, sign bool) (*Sm2Signature, error) {

	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))

	if sign == true {
		if sm2.has_private_key == false {
			return nil, errors.New("Not private key")
		}
	}

	ret := new(Sm2Signature)

	if sign == true {
		if C.sm2_sign_init(&ret.sm2_sign_ctx, &sm2.sm2_key, id_str, C.strlen(id_str)) != 1 {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if C.sm2_verify_init(&ret.sm2_sign_ctx, &sm2.sm2_key, id_str, C.strlen(id_str)) != 1 {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	ret.sign = sign

	return ret, nil
}

func (sig *Sm2Signature) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if sig.sign == true {
		if C.sm2_sign_update(&sig.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return errors.New("Libgmssl inner error")
		}
	} else {
		if C.sm2_verify_update(&sig.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return errors.New("Libgmssl inner error")
		}
	}
	return nil
}

func (sig *Sm2Signature) Sign() ([]byte, error) {
	if sig.sign != true {
		return nil, errors.New("Not signing state")
	}
	outbuf := make([]byte, C.SM2_MAX_SIGNATURE_SIZE)
	var outlen C.size_t
	if C.sm2_sign_finish(&sig.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (sig *Sm2Signature) Verify(signature []byte) bool {
	if sig.sign != false {
		return false
	}
	if C.sm2_verify_finish(&sig.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), C.size_t(len(signature))) != 1 {
		return false
	}
	return true
}



