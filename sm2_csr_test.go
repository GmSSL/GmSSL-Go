package gmssl

import (
	"strings"
	"testing"
)

func TestSm2CSRPEM(t *testing.T) {
	sm2, err := GenerateSm2Key()
	if err != nil {
		t.Fatalf("GenerateSm2Key() error = %v", err)
	}

	privateKeyPEM, err := sm2.ExportEncryptedPrivateKeyInfoPemToString("Password123!")
	if err != nil {
		t.Fatalf("ExportEncryptedPrivateKeyInfoPemToString() error = %v", err)
	}
	if !strings.HasPrefix(privateKeyPEM, "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		t.Fatalf("unexpected private key pem prefix: %q", privateKeyPEM)
	}

	publicKeyPEM, err := sm2.ExportPublicKeyInfoPemToString()
	if err != nil {
		t.Fatalf("ExportPublicKeyInfoPemToString() error = %v", err)
	}
	if !strings.HasPrefix(publicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("unexpected public key pem prefix: %q", publicKeyPEM)
	}

	expected := CSRSubject{
		CN: "China Unicom Root CA",
		O:  "China United Network Communications Group Co., Ltd.",
		OU: "Root CA",
		C:  "CN",
		L:  "Beijing",
		ST: "Beijing",
	}
	csrPEM, err := sm2.CreateCSRPEM(expected, Sm2DefaultId)
	if err != nil {
		t.Fatalf("CreateCSRPEM() error = %v", err)
	}
	if !strings.HasPrefix(csrPEM, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("unexpected csr pem prefix: %q", csrPEM)
	}
	if !VerifyCSRPEM(csrPEM, Sm2DefaultId) {
		t.Fatal("VerifyCSRPEM() returned false")
	}

	got, err := ParseCSRSubjectPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRSubjectPEM() error = %v", err)
	}
	if got != expected {
		t.Fatalf("ParseCSRSubjectPEM() = %#v, want %#v", got, expected)
	}
}

func TestSm2CSRWithoutOU(t *testing.T) {
	sm2, err := GenerateSm2Key()
	if err != nil {
		t.Fatalf("GenerateSm2Key() error = %v", err)
	}

	expected := CSRSubject{
		CN: "Example CSR",
		O:  "Example Org",
		C:  "CN",
		L:  "Shanghai",
		ST: "Shanghai",
	}
	csrPEM, err := sm2.CreateCSRPEM(expected, Sm2DefaultId)
	if err != nil {
		t.Fatalf("CreateCSRPEM() error = %v", err)
	}
	got, err := ParseCSRSubjectPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSRSubjectPEM() error = %v", err)
	}
	if got != expected {
		t.Fatalf("ParseCSRSubjectPEM() = %#v, want %#v", got, expected)
	}
}
