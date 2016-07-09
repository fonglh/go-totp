package main

import (
	//	"crypto/hmac"
	//"crypto/sha1"
	"encoding/base32"
	"fmt"
	"time"
)

func main() {

	key, err := decodeKey("ABCDEFGHIJKLMNOP")
	if err != nil {
		// err is already formatted by the decodeKey function
		fmt.Println(err)
	}
	fmt.Println(key)
	fmt.Println(intToBytes(currPeriod()))

	//	mac := hmac.New(sha1.New, "abc")
}

// The secret from most services implementing 2FA is given
// as a 16 character string. This is a base32 encoding of
// 10 bytes.
// This function converts the base32 encoded string into a byte
// array.
func decodeKey(base32Key string) ([]byte, error) {
	key, err := base32.StdEncoding.DecodeString(base32Key)
	if err != nil {
		return nil, fmt.Errorf("Error encountered during base32 decoding of secret: %v", err.Error())
	}

	return key, nil
}

// Gets current time interval from Unix epoch.
// Interval is 30 seconds.
func currPeriod() int64 {
	intervalNum := time.Now().Unix() / 30
	return intervalNum
}

// HMAC function takes a byte string as its message
// This byte string is converted from the interval number
// and is passed as the message to the HMAC function.
func intToBytes(val int64) []byte {
	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		result[i] = byte(val & 0xff)
		val = val >> 8 // equivalent to val / 256
	}

	return result
}
