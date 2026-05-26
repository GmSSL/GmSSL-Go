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
#include <gmssl/oid.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_req.h>

static int gmssl_copy_file_to_buffer(FILE *fp, char **out, size_t *outlen) {
	long size;
	char *buf;

	if (fflush(fp) != 0) {
		return -1;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		return -1;
	}
	size = ftell(fp);
	if (size < 0) {
		return -1;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		return -1;
	}

	buf = (char *)malloc((size_t)size + 1);
	if (!buf) {
		return -1;
	}
	if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		free(buf);
		return -1;
	}
	buf[size] = '\0';
	*out = buf;
	*outlen = (size_t)size;
	return 1;
}

static int gmssl_sm2_private_key_info_encrypt_to_pem_string(const SM2_KEY *key, const char *pass, char **out, size_t *outlen) {
	FILE *fp = tmpfile();
	int ret = -1;

	if (!fp) {
		return -1;
	}
	if (sm2_private_key_info_encrypt_to_pem(key, pass, fp) != 1) {
		goto end;
	}
	if (gmssl_copy_file_to_buffer(fp, out, outlen) != 1) {
		goto end;
	}
	ret = 1;
end:
	fclose(fp);
	return ret;
}

static int gmssl_sm2_public_key_info_to_pem_string(const SM2_KEY *key, char **out, size_t *outlen) {
	FILE *fp = tmpfile();
	int ret = -1;

	if (!fp) {
		return -1;
	}
	if (sm2_public_key_info_to_pem(key, fp) != 1) {
		goto end;
	}
	if (gmssl_copy_file_to_buffer(fp, out, outlen) != 1) {
		goto end;
	}
	ret = 1;
end:
	fclose(fp);
	return ret;
}

static int gmssl_x509_req_to_pem_string(const uint8_t *req, size_t reqlen, char **out, size_t *outlen) {
	FILE *fp = tmpfile();
	int ret = -1;

	if (!fp) {
		return -1;
	}
	if (x509_req_to_pem(req, reqlen, fp) != 1) {
		goto end;
	}
	if (gmssl_copy_file_to_buffer(fp, out, outlen) != 1) {
		goto end;
	}
	ret = 1;
end:
	fclose(fp);
	return ret;
}

static int gmssl_create_csr_pem(
	const SM2_KEY *key,
	const char *country,
	const char *state,
	const char *locality,
	const char *org,
	const char *org_unit,
	const char *common_name,
	const char *signer_id,
	char **out,
	size_t *outlen
) {
	uint8_t subject[256];
	size_t subject_len = 0;
	uint8_t attrs[1] = {0};
	size_t attrs_len = 0;
	uint8_t req[4096];
	uint8_t *p = req;
	size_t req_len = 0;

	if (x509_name_set(subject, &subject_len, sizeof(subject), country, state, locality, org, org_unit, common_name) != 1) {
		return -1;
	}
	if (x509_req_sign_to_der(
		X509_version_v1,
		subject, subject_len,
		key,
		attrs, attrs_len,
		OID_sm2sign_with_sm3,
		key, signer_id, strlen(signer_id),
		&p, &req_len) != 1) {
		return -1;
	}
	if (x509_req_verify(req, req_len, signer_id, strlen(signer_id)) != 1) {
		return -1;
	}
	return gmssl_x509_req_to_pem_string(req, req_len, out, outlen);
}

static int gmssl_parse_csr_subject_field(const char *pem, size_t pemlen, int oid, char **out, size_t *outlen) {
	FILE *fp = tmpfile();
	uint8_t req[4096];
	size_t reqlen = 0;
	int version = 0;
	const uint8_t *subject = NULL;
	size_t subject_len = 0;
	SM2_KEY subject_public_key;
	const uint8_t *attributes = NULL;
	size_t attributes_len = 0;
	int signature_algor = 0;
	int tag = 0;
	const uint8_t *val = NULL;
	size_t vlen = 0;
	int ret;

	if (!fp) {
		return -1;
	}
	if (pemlen > 0 && fwrite(pem, 1, pemlen, fp) != pemlen) {
		goto err;
	}
	rewind(fp);
	if (x509_req_from_pem(req, &reqlen, sizeof(req), fp) != 1) {
		goto err;
	}
	if (x509_req_get_details(
		req, reqlen,
		&version,
		&subject, &subject_len,
		&subject_public_key,
		&attributes, &attributes_len,
		&signature_algor,
		NULL, NULL) != 1) {
		goto err;
	}

	ret = x509_name_get_value_by_type(subject, subject_len, oid, &tag, &val, &vlen);
	if (ret < 0) {
		goto err;
	}
	*out = (char *)malloc(vlen + 1);
	if (!*out) {
		goto err;
	}
	if (ret == 1 && vlen > 0) {
		memcpy(*out, val, vlen);
	}
	(*out)[vlen] = '\0';
	*outlen = vlen;
	fclose(fp);
	return 1;

err:
	fclose(fp);
	return -1;
}

static int gmssl_verify_csr_pem(const char *pem, size_t pemlen, const char *signer_id) {
	FILE *fp = tmpfile();
	uint8_t req[4096];
	size_t reqlen = 0;
	int ret = -1;

	if (!fp) {
		return -1;
	}
	if (pemlen > 0 && fwrite(pem, 1, pemlen, fp) != pemlen) {
		goto end;
	}
	rewind(fp);
	if (x509_req_from_pem(req, &reqlen, sizeof(req), fp) != 1) {
		goto end;
	}
	if (x509_req_verify(req, reqlen, signer_id, strlen(signer_id)) != 1) {
		goto end;
	}
	ret = 1;
end:
	fclose(fp);
	return ret;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

type CSRSubject struct {
	CN string
	O  string
	OU string
	C  string
	L  string
	ST string
}

func cOptionalString(value string) (*C.char, func()) {
	if value == "" {
		return nil, func() {}
	}
	ptr := C.CString(value)
	return ptr, func() {
		C.free(unsafe.Pointer(ptr))
	}
}

func (sm2 *Sm2Key) ExportEncryptedPrivateKeyInfoPemToString(pass string) (string, error) {
	if sm2.has_private_key != true {
		return "", errors.New("Not private key")
	}

	passStr := C.CString(pass)
	defer C.free(unsafe.Pointer(passStr))

	var out *C.char
	var outlen C.size_t
	if C.gmssl_sm2_private_key_info_encrypt_to_pem_string(&sm2.sm2_key, passStr, &out, &outlen) != 1 {
		return "", errors.New("Libgmssl inner error")
	}
	defer C.free(unsafe.Pointer(out))

	return C.GoStringN(out, C.int(outlen)), nil
}

func (sm2 *Sm2Key) ExportPublicKeyInfoPemToString() (string, error) {
	var out *C.char
	var outlen C.size_t
	if C.gmssl_sm2_public_key_info_to_pem_string(&sm2.sm2_key, &out, &outlen) != 1 {
		return "", errors.New("Libgmssl inner error")
	}
	defer C.free(unsafe.Pointer(out))

	return C.GoStringN(out, C.int(outlen)), nil
}

func (sm2 *Sm2Key) CreateCSRPEM(subject CSRSubject, signerID string) (string, error) {
	if sm2.has_private_key != true {
		return "", errors.New("Not private key")
	}
	if signerID == "" {
		signerID = Sm2DefaultId
	}

	country := C.CString(subject.C)
	defer C.free(unsafe.Pointer(country))

	state, freeState := cOptionalString(subject.ST)
	defer freeState()

	locality, freeLocality := cOptionalString(subject.L)
	defer freeLocality()

	org, freeOrg := cOptionalString(subject.O)
	defer freeOrg()

	orgUnit, freeOrgUnit := cOptionalString(subject.OU)
	defer freeOrgUnit()

	commonName, freeCommonName := cOptionalString(subject.CN)
	defer freeCommonName()

	signerIDStr := C.CString(signerID)
	defer C.free(unsafe.Pointer(signerIDStr))

	var out *C.char
	var outlen C.size_t
	if C.gmssl_create_csr_pem(
		&sm2.sm2_key,
		country,
		state,
		locality,
		org,
		orgUnit,
		commonName,
		signerIDStr,
		&out,
		&outlen,
	) != 1 {
		return "", errors.New("Libgmssl inner error")
	}
	defer C.free(unsafe.Pointer(out))

	return C.GoStringN(out, C.int(outlen)), nil
}

func VerifyCSRPEM(csrPEM string, signerID string) bool {
	if signerID == "" {
		signerID = Sm2DefaultId
	}

	csr := C.CString(csrPEM)
	defer C.free(unsafe.Pointer(csr))

	id := C.CString(signerID)
	defer C.free(unsafe.Pointer(id))

	return C.gmssl_verify_csr_pem(csr, C.size_t(len(csrPEM)), id) == 1
}

func ParseCSRSubjectPEM(csrPEM string) (CSRSubject, error) {
	csr := C.CString(csrPEM)
	defer C.free(unsafe.Pointer(csr))

	parseField := func(oid C.int) (string, error) {
		var out *C.char
		var outlen C.size_t
		if C.gmssl_parse_csr_subject_field(csr, C.size_t(len(csrPEM)), oid, &out, &outlen) != 1 {
			return "", errors.New("Libgmssl inner error")
		}
		defer C.free(unsafe.Pointer(out))
		return C.GoStringN(out, C.int(outlen)), nil
	}

	subject := CSRSubject{}
	var err error

	if subject.CN, err = parseField(C.OID_at_common_name); err != nil {
		return CSRSubject{}, err
	}
	if subject.O, err = parseField(C.OID_at_organization_name); err != nil {
		return CSRSubject{}, err
	}
	if subject.OU, err = parseField(C.OID_at_organizational_unit_name); err != nil {
		return CSRSubject{}, err
	}
	if subject.C, err = parseField(C.OID_at_country_name); err != nil {
		return CSRSubject{}, err
	}
	if subject.L, err = parseField(C.OID_at_locality_name); err != nil {
		return CSRSubject{}, err
	}
	if subject.ST, err = parseField(C.OID_at_state_or_province_name); err != nil {
		return CSRSubject{}, err
	}
	return subject, nil
}
