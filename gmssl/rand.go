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
#include <gmssl/rand.h>
*/
import "C"

import (
	"errors"
)

func RandBytes(length int) ([]byte, error) {
	outbuf := make([]byte, length)
	if C.rand_bytes((*C.uchar)(&outbuf[0]), C.size_t(length)) <= 0 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:length], nil
}
