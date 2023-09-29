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
#include <gmssl/sm9.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
*/
import "C"

import (
	"unsafe"
	"errors"
)


const (
	Sm9MaxIdSize = 63
	Sm9MaxPlaintextSize = 255
	Sm9MaxCiphertextSize = 367
	Sm9SignatureSize = 104
)


type Sm9EncMasterKey struct {
	master_key C.SM9_ENC_MASTER_KEY
	has_private_key bool
}

func GenerateSm9EncMasterKey() (*Sm9EncMasterKey, error) {

	ret := new(Sm9EncMasterKey)

	if C.sm9_enc_master_key_generate(&ret.master_key) != 1{
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportEncryptedSm9EncMasterKeyInfoPem(path string, pass string) (*Sm9EncMasterKey, error) {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9EncMasterKey)

	if C.sm9_enc_master_key_info_decrypt_from_pem(&ret.master_key, pass_str, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportSm9EncMasterPublicKeyPem(path string) (*Sm9EncMasterKey, error) {

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9EncMasterKey)

	if C.sm9_enc_master_public_key_from_pem(&ret.master_key, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = false

	return ret, nil
}

func (sm9 *Sm9EncMasterKey) ExportEncryptedMasterKeyInfoPem(path string, pass string) error {

	if sm9.has_private_key != true {
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

	if C.sm9_enc_master_key_info_encrypt_to_pem(&sm9.master_key, pass_str, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm9 *Sm9EncMasterKey) ExportMasterPublicKeyPem(path string) error {
	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm9_enc_master_public_key_to_pem(&sm9.master_key, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm9 *Sm9EncMasterKey) ExtractKey(id string) (*Sm9EncKey, error) {
	if sm9.has_private_key != true {
		return nil, errors.New("Not private key")
	}

	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))

	ret := new(Sm9EncKey)

	if C.sm9_enc_master_key_extract_key(&sm9.master_key, id_str, C.strlen(id_str), &ret.key) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.id = id

	return ret, nil
}

func (sm9 *Sm9EncMasterKey) Encrypt(in []byte, to string) ([]byte, error) {

	if len(in) > C.SM9_MAX_PLAINTEXT_SIZE {
		return nil, errors.New("Plaintext too long")
	}

	to_str := C.CString(to)
	defer C.free(unsafe.Pointer(to_str))

	outbuf := make([]byte, C.SM9_MAX_CIPHERTEXT_SIZE)
	var outlen C.size_t

	if C.sm9_encrypt(&sm9.master_key, to_str, C.strlen(to_str),
		(*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}


type Sm9EncKey struct {
	key C.SM9_ENC_KEY
	id string
}

func ImportEncryptedSm9EncPrivateKeyInfoPem(path string, pass string, id string) (*Sm9EncKey, error) {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9EncKey)

	if C.sm9_enc_key_info_decrypt_from_pem(&ret.key, pass_str, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.id = id

	return ret, nil
}

func (sm9 *Sm9EncKey) GetId() string {
	return sm9.id
}

func (sm9 *Sm9EncKey) ExportEncryptedPrivateKeyInfoPem(path string, pass string) error {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm9_enc_key_info_encrypt_to_pem(&sm9.key, pass_str, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm9 *Sm9EncKey) Decrypt(in []byte) ([]byte, error) {

	id_str := C.CString(sm9.id)
	defer C.free(unsafe.Pointer(id_str))

	outbuf := make([]byte, C.SM9_MAX_PLAINTEXT_SIZE)
	var outlen C.size_t

	if C.sm9_decrypt(&sm9.key, id_str, C.strlen(id_str),
		(*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}


type Sm9SignMasterKey struct {
	master_key C.SM9_SIGN_MASTER_KEY
	has_private_key bool
}

func GenerateSm9SignMasterKey() (*Sm9SignMasterKey, error) {

	ret := new(Sm9SignMasterKey)

	if C.sm9_sign_master_key_generate(&ret.master_key) != 1{
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportEncryptedSm9SignMasterKeyInfoPem(path string, pass string) (*Sm9SignMasterKey, error) {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9SignMasterKey)

	if C.sm9_sign_master_key_info_decrypt_from_pem(&ret.master_key, pass_str, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = true

	return ret, nil
}

func ImportSm9SignMasterPublicKeyPem(path string) (*Sm9SignMasterKey, error) {

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9SignMasterKey)

	if C.sm9_sign_master_public_key_from_pem(&ret.master_key, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = false

	return ret, nil
}

func (sm9 *Sm9SignMasterKey) ExportEncryptedMasterKeyInfoPem(path string, pass string) error {

	if sm9.has_private_key != true {
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

	if C.sm9_sign_master_key_info_encrypt_to_pem(&sm9.master_key, pass_str, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm9 *Sm9SignMasterKey) ExportMasterPublicKeyPem(path string) error {
	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm9_sign_master_public_key_to_pem(&sm9.master_key, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sm9 *Sm9SignMasterKey) ExtractKey(id string) (*Sm9SignKey, error) {
	if sm9.has_private_key != true {
		return nil, errors.New("Not private key")
	}

	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))

	ret := new(Sm9SignKey)

	if C.sm9_sign_master_key_extract_key(&sm9.master_key, id_str, C.strlen(id_str), &ret.key) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.id = id

	return ret, nil
}



type Sm9SignKey struct {
	key C.SM9_SIGN_KEY
	id string
}

func ImportEncryptedSm9SignPrivateKeyInfoPem(path string, pass string, id string) (*Sm9SignKey, error) {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	ret := new(Sm9SignKey)

	if C.sm9_sign_key_info_decrypt_from_pem(&ret.key, pass_str, fp) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.id = id

	return ret, nil
}

func (sm9 *Sm9SignKey) GetId() string {
	return sm9.id
}

func (sm9 *Sm9SignKey) ExportEncryptedPrivateKeyInfoPem(path string, pass string) error {

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("wb"))
	if fp == nil {
		return errors.New("fopen failure")
	}
	defer C.fclose(fp)

	if C.sm9_sign_key_info_encrypt_to_pem(&sm9.key, pass_str, fp) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

type Sm9Signature struct {
	sm9_sign_ctx C.SM9_SIGN_CTX
	sign bool
}

func NewSm9Signature(sign bool) (*Sm9Signature, error) {

	ret := new(Sm9Signature)

	if sign == true {
		if C.sm9_sign_init(&ret.sm9_sign_ctx) != 1 {
			return nil, errors.New("Libgmssl inner error")
		}
	} else {
		if C.sm9_verify_init(&ret.sm9_sign_ctx) != 1 {
			return nil, errors.New("Libgmssl inner error")
		}
	}
	ret.sign = sign

	return ret, nil
}

func (sig *Sm9Signature) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if sig.sign == true {
		if C.sm9_sign_update(&sig.sm9_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return errors.New("Libgmssl inner error")
		}
	} else {
		if C.sm9_verify_update(&sig.sm9_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return errors.New("Libgmssl inner error")
		}
	}
	return nil
}

func (sig *Sm9Signature) Sign(sign_key *Sm9SignKey) ([]byte, error) {
	if sig.sign != true {
		return nil, errors.New("Not signing state")
	}

	outbuf := make([]byte, C.SM9_SIGNATURE_SIZE)
	var outlen C.size_t
	if C.sm9_sign_finish(&sig.sm9_sign_ctx, &sign_key.key, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (sig *Sm9Signature) Verify(signature []byte, master_public_key *Sm9SignMasterKey, signer_id string) bool {
	if sig.sign != false {
		return false
	}

	signer_id_str := C.CString(signer_id)
	defer C.free(unsafe.Pointer(signer_id_str))

	if C.sm9_verify_finish(&sig.sm9_sign_ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), C.size_t(len(signature)),
		&master_public_key.master_key, signer_id_str, C.strlen(signer_id_str)) != 1 {
		return false
	}
	return true
}

