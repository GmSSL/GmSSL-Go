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
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>



*/
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
	"time"
)


type Sm2Certificate struct {
	cert *C.uint8_t
	certlen C.size_t
}

func ImportSm2CertificatePem(path string) (*Sm2Certificate, error) {

	path_str := C.CString(path)
	defer C.free(unsafe.Pointer(path_str))

	fp := C.fopen(path_str, C.CString("rb"))
	if fp == nil {
		return nil, errors.New("fopen failure")
	}
	defer C.fclose(fp)

	var cert *C.uint8_t
	var certlen C.size_t

	if C.x509_cert_new_from_file(&cert, &certlen, path_str) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}

	ret := &Sm2Certificate{cert, certlen}
	runtime.SetFinalizer(ret, func(ret *Sm2Certificate) {
		C.free(unsafe.Pointer(ret.cert))
	})
	return ret, nil
}

func (cert *Sm2Certificate) GetSerialNumber() ([]byte, error) {
	var serial *C.uint8_t
	var serial_len C.size_t

	if C.x509_cert_get_issuer_and_serial_number(cert.cert, cert.certlen, nil, nil, &serial, &serial_len) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}

	outbuf := make([]byte, serial_len)
	C.memcpy(unsafe.Pointer(&outbuf[0]), unsafe.Pointer(serial), serial_len)
	return outbuf, nil
}

func (cert *Sm2Certificate) GetValidity() (time.Time, time.Time, error) {

	var not_before C.time_t
	var not_after C.time_t

	if C.x509_cert_get_details(cert.cert, cert.certlen,
		nil, nil, nil, nil, nil, nil,
		&not_before, &not_after,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil) != 1 {
		return time.Unix(0,0), time.Unix(0,0), errors.New("Libgmssl inner error")
	}

	return time.Unix(int64(not_before), 0), time.Unix(int64(not_after), 0), nil
}


func gmssl_parse_attr_type_and_value(name map[string]string, d *C.uint8_t, dlen C.size_t) error {
	var oid C.int
	var tag C.int
	var val *C.char
	var vlen C.size_t

	if C.x509_name_type_from_der(&oid, &d, &dlen) != 1 {
		return errors.New("libgmssl inner error")
	}
	oid_name := C.x509_name_type_name(oid)

	if oid == C.OID_email_address {
		if C.asn1_ia5_string_from_der_ex(C.ASN1_TAG_IA5String, &val, &vlen, &d, &dlen) != 1 {
			return errors.New("libgmssl inner error")
		}
		name[C.GoString(oid_name)] = C.GoStringN(val, C.int(vlen))

	} else {
		var uchar_ptr *C.uchar
		if C.x509_directory_name_from_der(&tag, &uchar_ptr, &vlen, &d, &dlen) != 1 {
			return errors.New("libgmssl inner error")
		}

		name[C.GoString(oid_name)] = C.GoStringN((*C.char)(unsafe.Pointer(uchar_ptr)), C.int(vlen))
	}

	if C.asn1_length_is_zero(dlen) != 1 {
		return errors.New("libgmssl inner error")
	}

	return nil;
}

func gmssl_parse_rdn(name map[string]string, d *C.uint8_t, dlen C.size_t) error {
	var p *C.uint8_t
	var plen C.size_t

	for dlen > 0 {
		if C.asn1_type_from_der(C.ASN1_TAG_SEQUENCE, &p, &plen, &d, &dlen) != 1 {
			return errors.New("libgmssl inner error")
		}
		if gmssl_parse_attr_type_and_value(name, p, plen) != nil {
			return errors.New("Parse RDN error")
		}
	}
	return nil
}

func gmssl_parse_name(name map[string]string, d *C.uint8_t, dlen C.size_t) error {
	var p *C.uint8_t
	var plen C.size_t

	for dlen > 0 {
		if C.asn1_nonempty_type_from_der(C.ASN1_TAG_SET, &p, &plen, &d, &dlen) != 1 {
			return errors.New("libgmssl inner error")
		}
		if gmssl_parse_rdn(name, p, plen) != nil {
			return errors.New("Parse name error")
		}
	}
	return nil
}

func (cert *Sm2Certificate) GetIssuer() ([]byte, map[string]string, error) {
	var issuer *C.uint8_t
	var issuer_len C.size_t

	if C.x509_cert_get_issuer(cert.cert, cert.certlen, &issuer, &issuer_len) != 1 {
		return nil, nil, errors.New("Libgmssl inner error")
	}

	name := make(map[string]string)

	if gmssl_parse_name(name, issuer, issuer_len) != nil {
		return nil, nil, errors.New("Libgmssl inner error")
	}

	raw_data := make([]byte, issuer_len)
	C.memcpy(unsafe.Pointer(&raw_data[0]), unsafe.Pointer(issuer), issuer_len)

	return raw_data, name, nil
}

func (cert *Sm2Certificate) GetSubject() ([]byte, map[string]string, error) {
	var subject *C.uint8_t
	var subject_len C.size_t

	if C.x509_cert_get_subject(cert.cert, cert.certlen, &subject, &subject_len) != 1 {
		return nil, nil, errors.New("Libgmssl inner error")
	}

	name := make(map[string]string)

	if gmssl_parse_name(name, subject, subject_len) != nil {
		return nil, nil, errors.New("Libgmssl inner error")
	}

	raw_data := make([]byte, subject_len)
	C.memcpy(unsafe.Pointer(&raw_data[0]), unsafe.Pointer(subject), subject_len)

	return raw_data, name, nil
}

func (cert *Sm2Certificate) GetSubjectPublicKey() (*Sm2Key, error) {

	ret := new(Sm2Key)

	if C.x509_cert_get_subject_public_key(cert.cert, cert.certlen, &ret.sm2_key) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	ret.has_private_key = false

	return ret, nil
}

func (cert *Sm2Certificate) VerifyByCaCertificate(ca_cert *Sm2Certificate, sm2_id string) bool {

	sm2_id_str := C.CString(sm2_id)
	defer C.free(unsafe.Pointer(sm2_id_str))

	if C.x509_cert_verify_by_ca_cert(cert.cert, cert.certlen, ca_cert.cert, ca_cert.certlen,
		sm2_id_str, C.strlen(sm2_id_str)) != 1 {
		return false
	}
	return true
}


