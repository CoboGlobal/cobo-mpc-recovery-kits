package wallet

import (
	"testing"

	"github.com/CoboGlobal/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/stretchr/testify/assert"
)

func TestGenerateXTNAddress(t *testing.T) {
	key, err := crypto.B58Deserialize("xpub6Fu7txWcpENRtHzK5uzyTeNsD15Zqf56A52WWmNjSJc3fqLyzHRjx9V8twNEsE1G6HCXxRMtbbQwn1KM42Eve8dapWiqhkH7cZ5j1GqbVnj")
	assert.NoError(t, err)
	addresses, err := GenerateXTNAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "tb1prs8ekfunf4yfq6epnz8q4zw39zykhkgz9hrprpgml4s3w04egzwsnhud60", TAPROOT))

	key, err = crypto.B58Deserialize("xpub6Fu7txWcpENRqfaVLYCHo4FnoFvxkG9UQ52xMxsi5XQuXFhqp36izQrPZqDWqr3P5rGbECP3Bzoc7j9HK1ZWFJe3FBsPZZ14NaDJKfyYGa5")
	assert.NoError(t, err)
	addresses, err = GenerateXTNAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "tb1q0px4kneptpwer2qqypd6hsvwgmg9r40tz5qws0", NATIVE_SEGWIT))

	key, err = crypto.B58Deserialize("xpub6Fu7txWcpENRnAtev4TYMcAwAZcNxMjr4hxGPZMu8eXgaC1HjS3dDqhaPkY6EHvzisyNa21aLnHYYZ8YQ1y3qTZSTfAvPHoh53T9ebe4CBa")
	assert.NoError(t, err)
	addresses, err = GenerateXTNAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "2MxgpWvNHAsXPRvZfxmRT2CXWAVzEuS2rtV", NESTED_SEGWIT))

	key, err = crypto.B58Deserialize("xpub6Fu7txWcpENRkFuTNw1dqziPS2vH6KK9K1k6WkVVq65fZYBhRLAh5j4kVKPtXQAYCgnoLtkkLYSmYWTuGi1Fx53GumKRyDGqtpR3CM69eNf")
	assert.NoError(t, err)
	addresses, err = GenerateXTNAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "ms95B9JosWfupRmNREmMZ112DsYCBC2Xu5", LEGACY))
}

func TestGenerateBTCAddress(t *testing.T) {
	key, err := crypto.B58Deserialize("xpub6Gp6PCF54nmH4gWS4spcdsVSibgjBGrkuyBXVG8hCjn1Cq99uk222YPhJouQm7Gmw2bKFpEk5MGrZBD9PQTDZsBcB9qXztKUcUoXUMCBSgD")
	assert.NoError(t, err)
	addresses, err := GenerateBTCAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "16EwA2beT2AgiipxJBc81527KP2kSogAMw", LEGACY))

	key, err = crypto.B58Deserialize("xpub6Gp6PCF54nmH2aS9w2CspDXe1KdfoQxWDJnQktWammDhjVdVSQtzvfD7pBJP7HAmQkYrjYgC4wh5z3cREYo3zUgSSCu3VeFNSJZPTs8jC8z")
	assert.NoError(t, err)
	addresses, err = GenerateBTCAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "36iDRpHScA9SLTYGkqmr2BThoDjp5w4r7x", NESTED_SEGWIT))

	key, err = crypto.B58Deserialize("xpub6Gp6PCF54nmGyHJ4x3FhkwRnVGXFZkErWjYSgXHYpBKSERiTnmteAqHKDWq3VGDgE789RZ8x2fVArp9W6dQNw9HwNVHVGZYrbabSixYoAP4")
	assert.NoError(t, err)
	addresses, err = GenerateBTCAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "bc1qgkal4qh29fklm7rw07f6rw6mpxr8thjxvuc7hk", NATIVE_SEGWIT))

	key, err = crypto.B58Deserialize("xpub6Gp6PCF54nmGwSdya4hyLwzaC3fLpApXCWdAuuragPRG6cxnnkJj6A9ic3sMeEzhtCyXGuLvYD4wEbnvvaiYbGk3ZsYWjE5Xcqn2KcYfZx3")
	assert.NoError(t, err)
	addresses, err = GenerateBTCAddresses(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 4)
	assert.True(t, foundAddress(addresses, "bc1peh6fpx7un7jfypedtnpylftl5uv92kdchqzu0ty9s354lccn8vxsfpp4jn", TAPROOT))
}

func TestGenerateEVMAddress(t *testing.T) {
	key, err := crypto.B58Deserialize("xpub6FXwXZ4feQjGX7ZXUdTB9cRuJuUJkzsWAQHejUBozkPgN9wwu7P7wNtuyRqiey52ES8PuZwmtgHHcVSFGH75RBthn8djN2fkdcbggtpRQQ2")
	assert.NoError(t, err)
	addresses, err := GenerateEVMAddress(key)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, addresses, 1)
	assert.True(t, foundAddress(addresses, "0xBe7f55D105BBacc2A963aef535d0d791D8911fB2", ""))
}

func foundAddress(addresses []Address, address string, addressType string) bool {
	found := false
	for _, addr := range addresses {
		if address == addr.Address && addressType == addr.Type {
			found = true
			break
		}
	}
	return found
}
