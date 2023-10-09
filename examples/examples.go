package main

import (
	"fmt"
	"github.com/GmSSL/GmSSL-Go"
)

func main() {
	fmt.Printf("GmSSL-Go Version: %s\n", gmssl.GmSSLGoVersion)
	fmt.Printf("GmSSL Library Version: %s\n", gmssl.GetGmSSLLibraryVersion())

	key, _ := gmssl.RandBytes(16)
	fmt.Printf("RandBytes(32) : %x\n", key)

	fmt.Printf("Sm3DigestSize : %d\n", gmssl.Sm3DigestSize)

	sm3 := gmssl.NewSm3()
	sm3.Update([]byte("abc"))
	dgst := sm3.Digest()
	fmt.Printf("Sm3('abc') : %x\n", dgst)

	fmt.Printf("Sm3HmacMinKeySize = %d\n", gmssl.Sm3HmacMinKeySize)
	fmt.Printf("Sm3HmacMaxKeySize = %d\n", gmssl.Sm3HmacMaxKeySize)
	fmt.Printf("Sm3HmacSize = %d\n", gmssl.Sm3HmacSize)

	hmac, _ := gmssl.NewSm3Hmac(key)
	hmac.Update([]byte("abc"))
	mac := hmac.GenerateMac()
	fmt.Printf("Sm3Hmac('abc') : %x\n", mac)

	fmt.Printf("Sm3Pbkdf2MinIter = %d\n", gmssl.Sm3Pbkdf2MinIter)
	fmt.Printf("Sm3Pbkdf2MaxIter = %d\n", gmssl.Sm3Pbkdf2MaxIter)
	fmt.Printf("Sm3Pbkdf2MaxSaltSize = %d\n", gmssl.Sm3Pbkdf2MaxSaltSize)
	fmt.Printf("Sm3Pbkdf2DefaultSaltSize = %d\n", gmssl.Sm3Pbkdf2DefaultSaltSize)
	fmt.Printf("Sm3Pbkdf2MaxKeySize = %d\n", gmssl.Sm3Pbkdf2MaxKeySize)

	salt, _ := gmssl.RandBytes(gmssl.Sm3Pbkdf2DefaultSaltSize)
	kdf_key, _ := gmssl.Sm3Pbkdf2("Password", salt, gmssl.Sm3Pbkdf2MinIter, gmssl.Sm3HmacMinKeySize)
	fmt.Printf("Sm3Pbkdf2('Password') : %x\n", kdf_key)

	fmt.Printf("Sm4KeySize = %d\n", gmssl.Sm4KeySize)
	fmt.Printf("Sm4BlockSize = %d\n", gmssl.Sm4BlockSize)

	block, _ := gmssl.RandBytes(gmssl.Sm4BlockSize)
	sm4_enc, _ := gmssl.NewSm4(key, true)
	cblock, _ := sm4_enc.Encrypt(block)
	fmt.Printf("SM4 Plaintext : %x\n", block)
	fmt.Printf("SM4 Ciphertext: %x\n", cblock)

	sm4_dec, _ := gmssl.NewSm4(key, false)
	dblock, _ := sm4_dec.Encrypt(cblock)
	fmt.Printf("SM4 Decrypted : %x\n", dblock)

	fmt.Printf("Sm4CbcIvSize = %d\n", gmssl.Sm4CbcIvSize)
	iv, _ := gmssl.RandBytes(gmssl.Sm4CbcIvSize)

	sm4_cbc_enc, _ := gmssl.NewSm4Cbc(key, iv, true)
	cbc_ciphertext, _ := sm4_cbc_enc.Update([]byte("abc"))
	cbc_ciphertext_last, _ := sm4_cbc_enc.Finish()
	cbc_ciphertext = append(cbc_ciphertext, cbc_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", cbc_ciphertext)
	sm4_cbc_dec, _ := gmssl.NewSm4Cbc(key, iv, false)
	cbc_plaintext, _ := sm4_cbc_dec.Update(cbc_ciphertext)
	cbc_plaintext_last, _ := sm4_cbc_dec.Finish()
	cbc_plaintext = append(cbc_plaintext, cbc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", cbc_plaintext)

	sm4_ctr, _ := gmssl.NewSm4Ctr(key, iv)
	ctr_ciphertext, _ := sm4_ctr.Update([]byte("abc"))
	ctr_ciphertext_last, _ := sm4_ctr.Finish()
	ctr_ciphertext = append(ctr_ciphertext, ctr_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", ctr_ciphertext)

	sm4_ctr, _ = gmssl.NewSm4Ctr(key, iv)
	ctr_plaintext, _ := sm4_ctr.Update(ctr_ciphertext)
	ctr_plaintext_last, _ := sm4_ctr.Finish()
	ctr_plaintext = append(ctr_plaintext, ctr_plaintext_last...)
	fmt.Printf("plaintext = %x\n", ctr_plaintext)


	fmt.Printf("Sm4GcmMinIvSize = %d\n", gmssl.Sm4GcmMinIvSize)
	fmt.Printf("Sm4GcmMinIvSize = %d\n", gmssl.Sm4GcmMinIvSize)
	fmt.Printf("Sm4GcmDefaultIvSize = %d\n", gmssl.Sm4GcmDefaultIvSize)
	fmt.Printf("Sm4GcmDefaultTagSize = %d\n", gmssl.Sm4GcmDefaultTagSize)
	fmt.Printf("Sm4GcmMaxTagSize = %d\n", gmssl.Sm4GcmMaxTagSize)
	aad, _ := gmssl.RandBytes(20)
	taglen := gmssl.Sm4GcmDefaultTagSize
	iv, _ = gmssl.RandBytes(gmssl.Sm4GcmDefaultIvSize)

	sm4_gcm_enc, _ := gmssl.NewSm4Gcm(key, iv, aad, taglen, true)
	gcm_ciphertext, _ := sm4_gcm_enc.Update([]byte("abc"))
	gcm_ciphertext_last, _ := sm4_gcm_enc.Finish()
	gcm_ciphertext = append(gcm_ciphertext, gcm_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", gcm_ciphertext)
	sm4_gcm_dec, _ := gmssl.NewSm4Gcm(key, iv, aad, taglen, false)
	gcm_plaintext, _ := sm4_gcm_dec.Update(gcm_ciphertext)
	gcm_plaintext_last, _ := sm4_gcm_dec.Finish()
	gcm_plaintext = append(gcm_plaintext, gcm_plaintext_last...)
	fmt.Printf("plaintext = %x\n", gcm_plaintext)


	fmt.Printf("ZucKeySize = %d\n", gmssl.ZucKeySize)
	fmt.Printf("ZucIvSize = %d\n", gmssl.ZucIvSize)
	iv, _ = gmssl.RandBytes(gmssl.ZucIvSize)

	zuc, _ := gmssl.NewZuc(key, iv)
	zuc_ciphertext, _ := zuc.Update([]byte("abc"))
	zuc_ciphertext_last, _ := zuc.Finish()
	zuc_ciphertext = append(zuc_ciphertext, zuc_ciphertext_last...)
	zuc, _ = gmssl.NewZuc(key, iv)
	zuc_plaintext, _ := zuc.Update(zuc_ciphertext)
	zuc_plaintext_last, _ := zuc.Finish()
	zuc_plaintext = append(zuc_plaintext, zuc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", zuc_plaintext)

	fmt.Printf("Sm2DefaultId = %s\n", gmssl.Sm2DefaultId)
	fmt.Printf("Sm2MaxSignatureSize = %d\n", gmssl.Sm2MaxSignatureSize)
	fmt.Printf("Sm2MinPlaintextSize = %d\n", gmssl.Sm2MinPlaintextSize)
	fmt.Printf("Sm2MaxPlaintextSize = %d\n", gmssl.Sm2MaxPlaintextSize)
	fmt.Printf("Sm2MinCiphertextSize = %d\n", gmssl.Sm2MinCiphertextSize)
	fmt.Printf("Sm2MaxCiphertextSize = %d\n", gmssl.Sm2MaxCiphertextSize)

	sm2, _ := gmssl.GenerateSm2Key()
	sm2.ExportEncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2.ExportPublicKeyInfoPem("sm2pub.pem")
	sm2pri, _ := gmssl.ImportSm2EncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2pub, _ := gmssl.ImportSm2PublicKeyInfoPem("sm2pub.pem")
	z, _ := sm2pub.ComputeZ(gmssl.Sm2DefaultId)
	fmt.Printf("Z = %x\n", z)
	Z, _ := sm2pri.ComputeZ(gmssl.Sm2DefaultId)
	fmt.Printf("Z = %x\n", Z)

	signature, _ := sm2pri.Sign(dgst)
	fmt.Printf("Signature = %x\n", signature)
	ret := sm2pub.Verify(dgst, signature)
	fmt.Print("Verify success = ", ret, "\n")


	sign, _ := gmssl.NewSm2Signature(sm2pri, gmssl.Sm2DefaultId, true)
	sign.Update([]byte("abc"))
	signature1, _ := sign.Sign()
	fmt.Printf("Sm2Signature Signature = %x\n", signature1)

	sign, _ = gmssl.NewSm2Signature(sm2pub, gmssl.Sm2DefaultId, false)
	sign.Update([]byte("abc"))
	ret1 := sign.Verify(signature1)
	fmt.Print("Sm2Signature Verify success = ", ret1, "\n")


	sm2_ciphertext, _ := sm2pub.Encrypt([]byte("abc"))
	sm2_plaintext, _ := sm2pri.Decrypt(sm2_ciphertext)
	fmt.Printf("SM2 Ciphertext : %x\n", sm2_ciphertext)
	fmt.Printf("SM2 Plaintext : %s\n", sm2_plaintext)

	fmt.Printf("Sm9MaxIdSize = %d\n", gmssl.Sm9MaxIdSize)
	fmt.Printf("Sm9MaxPlaintextSize = %d\n", gmssl.Sm9MaxPlaintextSize)
	fmt.Printf("Sm9MaxCiphertextSize = %d\n", gmssl.Sm9MaxCiphertextSize)
	fmt.Printf("Sm9SignatureSize = %d\n", gmssl.Sm9SignatureSize)

	sm9_enc_master, _ := gmssl.GenerateSm9EncMasterKey()
	sm9_enc_master.ExportEncryptedMasterKeyInfoPem("sm9enc.pem", "password")
	sm9_enc_master.ExportMasterPublicKeyPem("sm9encpub.pem")

	sm9_enc_master, _ = gmssl.ImportEncryptedSm9EncMasterKeyInfoPem("sm9enc.pem", "password")
	sm9_enc_master_pub, _ := gmssl.ImportSm9EncMasterPublicKeyPem("sm9encpub.pem")

	sm9_ciphertext, _ := sm9_enc_master_pub.Encrypt([]byte("plaintext"), "Alice")
	fmt.Printf("SM9 Ciphertext : %x\n", sm9_ciphertext)

	sm9_enc_key, _ := sm9_enc_master.ExtractKey("Alice")
	fmt.Printf("Id : %s\n", sm9_enc_key.GetId())
	sm9_enc_key.ExportEncryptedPrivateKeyInfoPem("sm9encpri.pem", "password")
	sm9_enc_key, _ = gmssl.ImportEncryptedSm9EncPrivateKeyInfoPem("sm9encpri.pem", "password", "Alice")

	sm9_plaintext, _ := sm9_enc_key.Decrypt(sm9_ciphertext)
	fmt.Printf("SM9 Plaintext : %s\n", sm9_plaintext)

	sm9_sign_master, _ := gmssl.GenerateSm9SignMasterKey()
	sm9_sign_master.ExportEncryptedMasterKeyInfoPem("sm9sign.pem", "password")
	sm9_sign_master.ExportMasterPublicKeyPem("sm9signpub.pem")

	sm9_sign_master, _ = gmssl.ImportEncryptedSm9SignMasterKeyInfoPem("sm9sign.pem", "password")
	sm9_sign_master_pub, _ := gmssl.ImportSm9SignMasterPublicKeyPem("sm9signpub.pem")

	sm9_sign_key, _ := sm9_sign_master.ExtractKey("Alice")
	fmt.Printf("Id : %s\n", sm9_sign_key.GetId())
	sm9_sign_key.ExportEncryptedPrivateKeyInfoPem("sm9signpri.pem", "password")
	sm9_sign_key, _ = gmssl.ImportEncryptedSm9SignPrivateKeyInfoPem("sm9signpri.pem", "password", "Alice")

	sm9_sign, _ := gmssl.NewSm9Signature(true)
	sm9_sign.Update([]byte("abc"))
	sm9_signature, _ := sm9_sign.Sign(sm9_sign_key)
	fmt.Printf("SM9 Signature : %x\n", sm9_signature)

	sm9_verify, _ := gmssl.NewSm9Signature(false)
	sm9_verify.Update([]byte("abc"))
	sm9_verify_ret := sm9_verify.Verify(sm9_signature, sm9_sign_master_pub, "Alice")
	fmt.Print("Sm9 Verify success : ", sm9_verify_ret, "\n")

	/*
	cert, _ := gmssl.ImportSm2CertificatePem("ROOTCA.pem")
	serial, _ := cert.GetSerialNumber()
	fmt.Printf("SerialNumber : %x\n", serial)

	not_before, not_after, _ := cert.GetValidity()
	fmt.Println("NotBefore : ", not_before)
	fmt.Println("NotAfter : ", not_after)


	issuer_raw, issuer, _ := cert.GetIssuer()
	fmt.Println("Issuer: ", issuer)
	fmt.Printf("Issuer (raw) : %x\n", issuer_raw)

	subject_raw, subject, _ := cert.GetSubject()
	fmt.Println("Subject: ", subject)
	fmt.Printf("Subject (raw) : %x\n", subject_raw)


	subject_public_key, _ := cert.GetSubjectPublicKey()
	subject_public_key.ExportPublicKeyInfoPem("subject_public_key.pem")

	cert_verify_ret := cert.VerifyByCaCertificate(cert, gmssl.Sm2DefaultId)
	fmt.Println("Cert Verify success : ", cert_verify_ret)
	*/
}



