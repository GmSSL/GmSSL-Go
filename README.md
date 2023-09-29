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

首先创建一个新项目，并初始化模块

```bash
$ mkdir hello
$ cd hello
```

创建源文件`hello.go`

```go
package main

import (
	"fmt"
	"gmssl"
)

func main() {
	fmt.Println(gmssl.GetGmSSLLibraryVersion())
}
```

```bash
$ go mod init example.com/hello
go: creating new go.mod: module example.com/hello
```

在项目模块中安装GmSSL-Go

```bash
$ go get github.com/GmSSL/GmSSL-Go@latest
go: added github.com/GmSSL/GmSSL-Go v1.3.0
```

打开文件`go.mod`，内容如下
```
module example.com/hello

go 1.21.1

require github.com/GmSSL/GmSSL-Go v1.3.0 // indirect
```

在文件`go.mod`最后面添加一行
```
replace gmssl => github.com/GmSSL/GmSSL-Go v1.3.0
```

更新模块信息
```bash
$ go mod tidy
go: found gmssl in gmssl v0.0.0-00010101000000-000000000000
```

编译执行
```bash
$ go build
$ go run .
GmSSL 3.1.1 Dev
```

