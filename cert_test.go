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
	"fmt"
	"os"
	"testing"
)

func TestCert(t *testing.T) {

	text :=`-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----`

	file, _ := os.Create("ROOTCA.pem")
	file.WriteString(text)
	file.Close()

	cert, _ := ImportSm2CertificatePem("ROOTCA.pem")

	serial, _ := cert.GetSerialNumber()
	fmt.Printf("Serial : %x\n", serial)

	not_before, not_after, _ := cert.GetValidity()
	fmt.Println("NotBefore : ", not_before)
	fmt.Println("NotAfter : ", not_after)

	issuer_raw, issuer, _ := cert.GetIssuer()
	fmt.Printf("Issuer Raw : %x\n", issuer_raw)
	fmt.Println("Issuer : ", issuer)

	subject_raw, subject, _ := cert.GetSubject()
	fmt.Printf("Subject Raw : %x\n", subject_raw)
	fmt.Println("subject : ", subject)

	subject_public_key, _ := cert.GetSubjectPublicKey()
	subject_public_key.ExportPublicKeyInfoPem("subject_public_key.pem")

	cert_verify_ret := cert.VerifyByCaCertificate(cert, Sm2DefaultId)
	if cert_verify_ret != true {
		t.Error("Test failure")
	}
}

