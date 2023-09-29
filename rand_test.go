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
	"testing"
)

func TestRand(t *testing.T) {

	rand, _ := RandBytes(128)

	if len(rand) != 128 {
		t.Error("Test failure")
	}
}

