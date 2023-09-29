# GmSSL-Go

## 简介

GmSSL-Go 是GmSSL密码库 https://github.com/guanzhi/GmSSL 的Go语言封装，以`cgo`方式实现，通过Go类和函数提供了如下密码接口：

* 密码随机数生成器
* SM2加密和签名，SM2密钥生成、私钥口令加密保护、密钥PEM文件导入导出
* SM2数字证书的导入、解析和验证
* SM3哈希函数、HMAC-SM3消息认证码、基于SM3的PBKDF2密钥导出函数
* SM4分组加密，以及SM4的CBC、CTR、GCM三种加密模式
* SM9加密和签名，以及SM9密钥生成、密钥口令加密保护、密钥PEM文件导入导出
* ZUC序列密码加密

目前GmSSL-Go功能可以覆盖除SSL/TLS/TLCP之外的国密算法主要应用开发场景。

## 开发入门

GmSSL-Go的库代码位于`gmssl`目录下，示例位于`examples`目录下。在源代码的`examples`目录下执行

```bash
go run .
```

可以执行默认的测试程序，查看`examples/hello.go`了解更多用法。

