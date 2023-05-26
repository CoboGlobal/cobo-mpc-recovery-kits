package crypto

import (
	"math/big"
	"testing"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	"github.com/stretchr/testify/assert"
)

type testKey struct {
	pathFragment uint32
	hexPrivKey   string
	chaincode    string
	hexPubkey    string
	extPrivKey   string
	extPubKey    string
	children     []testKey
}

func TestKeyCKD(t *testing.T) {
	vector1 := testKey{
		hexPrivKey: "0x0514cc3d8b25fb42a06c85a733c291895a27a336c32d8ef75329e7ab65d48386",
		chaincode:  "0x7341985dca4b24e32afacbe8047529d2cbfa9de2abdd91b3f9cc346f52885a90",
		hexPubkey:  "0x009d7bd2363a0b0a03830311ed027c509ec7f3ccc1fe6bd94b9db0c96a9b3f3c26",
		extPrivKey: "cprv3NNjUWyx1RBi3H5V8GgxywS8GRLt6PntM2dkf8ZeRfmBukJ2iYs1fsoDcXeXGstHPH18FufK9z2KyRRpW2eh3MwhgHNd7VDCPuvU6pYsoig",
		extPubKey:  "cpubGCmTMqXYTnzkbj4boYV9RcocrSYG1bSr8QuiRnEdhspzhvURRoBwV4iU7TnBKRRbmgHSAymckcRckZoNSR8SRK13n5ztB3pneN4xJSePBvG",
		children: []testKey{
			{
				pathFragment: 0,
				hexPrivKey:   "0x0d39d75540e518d4220078d74f86590070f43ef7bf3805dc04d8eefe12385487",
				chaincode:    "0x2389941d9d49974e91bd7877b8275422e2c663053d6aa31bfa9e85f43fe28f30",
				hexPubkey:    "0x00c9417ebec7df9859d9cc9b7d16d9c8b5bbcd91324731177a45696792bb49d3b3",
				extPrivKey:   "cprv3RbSKDst833rETUMYtVj62SbNhsYev3u3XeYXrnFm8vPVXKZ5ngYs9KEBD8hEUjb9PQdMsyDqg1XdLcBz91xEyfqNrRvqkjNvF2tNzSuEHs",
				extPubKey:    "cpubGFzACYRUaQrtnuTUEAHuXhp5xj4va7hrpuvWJWTF3LzCHhVwo31UgLEUg9Y3LFmWqBxxaWFGDJQkAHMHMT9BjjooXthHnMJrWULFQrQsdgL",
			},
			{
				pathFragment: 1,
				hexPrivKey:   "0x011fd5ad72f4200978d8fbb7dd1338b78d7575018e4d3ad3b2b0277760714e5d",
				chaincode:    "0xbe06b9785b463ad549d552846a60e3ba48c9b1eab49fdf8829d227c112cb3948",
				hexPubkey:    "0x006a8973f9ec79218dd852ab78f74cb6ee8e6411ce552534314452bf7e874306d5",
				extPrivKey:   "cprv3SDZT3zxLn8ZsZHpTA2bzQUM9P1fafjRKYGgt7KCHjwLH587Ax7xAi6ptGcXvxcXwtq14XkkXZGi2FSKoFwCiL53EHGWiB9uMtF3QCz1pJf",
				extPubKey:    "cpubGGcHLNYYo9wcS1Gw8RpnS5qqjQD3VsPP6vYeekzBZx195FJVtCSsyu25PCPVgWYTHtHbVoLiwY9FUFUjY8JW76693pooe6ZoCDXhEWkT4Fc",
			},
			{
				pathFragment: 2,
				hexPrivKey:   "0x039737b191c91d5c055d2c74ec98d88e2cf8b67364919d5d45f5239269691efb",
				chaincode:    "0x8e1e22c1f77925c1ac952659d1aacf3fbede98c625489b9cd4fb6c7f07298988",
				hexPubkey:    "0x00255fabd995f32a304f8033274db336dfcc2dea8ca09cf58786b26d5b888eeedb",
				extPrivKey:   "cprv3UuzaaCnbANkwWhzSYcYwKnUK4Zey8dyfRf688aikacdT4kx459jqK3hr7xgjPdHUPfxFiEMdMnd7hpr8GXVs6HVcZjgMuo6vv1mLWpubCj",
				extPubKey:    "cpubGKJiTtkP3YBoVxh77pQjP19xu5m2tLHwSow3tnFi2ngSFEwLmKUfeVxxM3C6oTgXz4bAnAkyCyyes8PQLLW7BcV6YfXhhRfZgoN2dQBKXQD",
			},
			{
				pathFragment: 2,
				hexPrivKey:   "0x053f8afd852542c3d509d812c74fedb84a2694587e840a3489ec1f79826fd92e",
				chaincode:    "0x6476f239cc4d5ed48f261f76c51f028613d523f19b200f1782f6951d58662508",
				hexPubkey:    "0x0051c15e02a44579254a9dab4a67bfe13d73eb73bdafb0bb6f6667094c9d5f5c30",
				extPrivKey:   "cprv3X5cVEmaMGcuhpuXi4s27bfiHZM8aPU7SxHSBUmjNexdrXmNeHquZpscUhLeKX7Dx8yGmaRSF6NsLuPAYGt8ypD1RGL7kKa2VBwBUBzrrc3",
				extPubKey:    "cpubGMULNZKAoeRxGGtePLfCZH3CsaYWVb85ELZPx8Sies2SehwmMYAqP1nryctsiiuhcdRmmEyLwRX2UeFyzvzgTWGbcpfPN2EJmFcHZ2Ad7Hm",
			},
			{
				pathFragment: 1000000000,
				hexPrivKey:   "0x052eecfd6fdf0d6e7d895d7c812b876b6b8da0d9a368d045886ea0a22e69c3cc",
				chaincode:    "0xa57fa7c7fb35482e5abc0253bd009136122c4aa975cdfaae5220f92804e8b174",
				hexPubkey:    "0x006f388b24da50a4ff70d981bde95eb023fda6068756f4664af03b4f665075e0df",
				extPrivKey:   "cprv3ZGAMxkse8vEmZQ4u5Vq7aFVjeDSLHkbShEJ7GmPrnjw9Tt8XYqNPiHHy3sZyTkXuMoNQz4jCMZxpJgMyeynAG7PENdmScjZZYky6Ww48kL",
				extPubKey:    "cpubGPetFHJU6WjHL1PBaMJ1ZFczKfQpFVQZE5WFsvSP8zojwe4XEoAJCuCYTyeogy2oUQmYpzs8wLrbuSDc47zVifDSMrdhWZfW564AZj9kNix",
			},
		},
	}

	vector2 := testKey{
		hexPrivKey: "0x00008a6d493a7e923adbba38b28de1b8d288799599b5b0fac0702305b66c03ca",
		chaincode:  "0xeca2f159d25d3914004329353b93822b5dff898aa8c092ecc0eccb36094cb270",
		hexPubkey:  "0x005958d526e7ef217392b93cb73552505e96453cfb926a0d10db9a834be717dce8",
		extPrivKey: "cprv3NNjUWyx1RBi4VAmHQHUdbmcKQoqL6jLeUJPARC2ZHbiHJqzww7AyN5qoarSm8D85ZXnMCNRfjWVLPbhjy9DtDGLanf1cDyjAwfm2zbxN9s",
		extPubKey:  "cpubGCmTMqXYTnzkcw9sxg5f5H96uS1DFJPJRraLw4s1qVfX5V2PfBS6nZ16JWWL5tWJBFNBRaHSRhz1xsLamQ8tTm1kT3yWiHS4T2VZEdPtRxe",
		children: []testKey{
			{
				pathFragment: 0,
				hexPrivKey:   "0x01e89a7230c737d186071ac055807a07ba236842a99ba995e824940454e391f6",
				chaincode:    "0x79d9b3446a9f2ccd5b8f2f8cbe247e69561c9b0b9ecd34b0d25c81b2b1b1e3bc",
				hexPubkey:    "0x00d7fde48487fae21b2e998f60ac01dec83782fb96e37557d5ba215325c6ad8861",
				extPrivKey:   "cprv3S4b5WcJHvGGhFgxYQ3YnE3mqBUGyqrK8eTdXj9a96yMeaW3sfsKYLxLox1CGgVtW195XBi82iKFtUuaTP9MKLLNx7Rh5y6zrBVYxNs84vi",
				extPubKey:    "cpubGGTJxq9tkJ5KFhg5DfqjDuRGRCfeu3WGv2jbJNpZRK3ASkgSavCFMXsbJtc1sCsYyHkkXmhRDGhoQeTPYoPB1XQYoSwD9vELfUMAsQHAuEg",
			},
			{
				pathFragment: 2147483647,
				hexPrivKey:   "0x01a01826e4976cefef795c517c384fe80fb895b1b88dfd3195b6e7ad05afb266",
				chaincode:    "0x5447581497c00d8c695acf0b9a04f6daf31a07efd0123ec612eed1680f85ea92",
				hexPubkey:    "0x00da93ac4cefd670fac303119d6b64260fd8dd12529ef7f6679916b8e99b7bf64d",
				extPrivKey:   "cprv3THVoFE4oD2BirJMxVFiAknWTXfAPveEivd2cj7cPA1sJJNwV5meJ2pssyBY6tZXezHo3c6Qn8h2c4Yitwbxwbfo5ynWGukBbyxsx9T2LCY",
				extPubKey:    "cpubGHgDgZmfFaqEHJHUdm3tcSA13YrYK8JCWJtzPNnbfN5g6UZLCL6a7Dk8NuocxvEKKkTcpdBL6b8zamF2skJwg3ohximB5oE6Pgh1hqAFHWX",
			},
			{
				pathFragment: 1,
				hexPrivKey:   "0x0bb1391f94660f40134d9787a7299f5893609f4b1e6a8e27bf9a282f4d743159",
				chaincode:    "0xa98647cf78e35b7eadb31d094d9a74901f19f2b7b373e619c506c5be64a8a652",
				hexPubkey:    "0x005cfb62819f355410b35604b8f1c3d7894444e71047c422e8f6eac0ccc16db38e",
				extPrivKey:   "cprv3VahrMN77564VnjjnEKJBARd9QSSeRVwybaYEJ3KegXrWPmdC2DL6tkTDxGi1jsjPJVdrNqvh7yijhkF54n7eqHiC1XSHBZoExjpmSKr6EB",
				extPubKey:    "cpubGKyRjfuhZSu74EirTW7Ucqo7jRdpZd9ukyrVzwiJvtbfJZx1uGYFv5fhiss3aUJKCttaewtZdrSwZnUbFRU1mnqmKgDdsc3Yjncp13nsEg6",
			},
			{
				pathFragment: 2147483646,
				hexPrivKey:   "0x06abd8f86d448c0fa4085286ed8c0fc3f30a7a2bf37c7c46225e6fc01ebfc2b9",
				chaincode:    "0x95a176582775adb23eaa9f730ad82e33307255a9a9110557cadd40fd8ac4b687",
				hexPubkey:    "0x005645aade9dc6241d3c42563502cd205cda4405b7f44fdbff2ea40f9ef96372f2",
				extPrivKey:   "cprv3WKPobGsa6xBg7k6KqbgdQ4JJGXgAfkodg3cNqU4hEcZEqA2o5yMHLbuLPpNxXPJNPGA8ovbBUJLVsFh3paQ37XhHfQWZ8YndjDQn3UggK5",
				extPubKey:    "cpubGLi7gupU2UmEEZjD17Ps55RntHj45sQmR4Ka9V93ySgN31LRWLJH6XX9qKPyPC9G3dip9NSP5Bc4Fty37uZ6cUrpZWkNxVDFZpX4dRJSrJD",
			},
			{
				pathFragment: 2,
				hexPrivKey:   "0x0b86709e0db33172a13cb7d60d0cd923862c1455e7424f4e37b692bfebb24fcf",
				chaincode:    "0xff75211da630c1b918b0ef75e19245e7dc52e0c3b9c73af632e7b98debbb5839",
				hexPubkey:    "0x0036e731a87c40706463ae6a8c39a0eedc2568fb7041eee5e18e1267e6a002b729",
				extPrivKey:   "cprv3YLGjkfEKTwcooWDCCGk4tVWJ53uWhnZ1gutzhSmvWd8shGNavZCUKCcgBYpx6Kwkcsbg8deqQiiVhUvjmvn1NDV5JBqnQD2NV7NoQaQubQ",
				extPubKey:    "cpubGNizd5CpmqkfNFVKsU4vWZrzt6FHRuSWo5BrmM7mCigwfsSmJAt8HW7sB6rU7MEvyKct1QVjj5Ni7qZgaASZsH53yvb8mCdhE1u54PzvmVs",
			},
		},
	}
	testPrivateKey(t, vector1)
	testPublicKey(t, vector1)
	testPrivateKey(t, vector2)
	testPublicKey(t, vector2)
}

func testPrivateKey(t *testing.T, vector testKey) {
	t.Helper()
	k, err := utils.Decode(vector.hexPrivKey)
	assert.NoError(t, err)
	d := new(big.Int).SetBytes(k)
	privKey, err := CreateEDDSAPrivateKey(d)
	assert.NoError(t, err)

	assert.Equal(t, vector.hexPrivKey, utils.Encode(privKey.Serialize()))
	assert.Equal(t, vector.hexPubkey, utils.Encode(CompressEDDSAPubKey(privKey.PubKey())))

	cc, err := utils.Decode(vector.chaincode)
	assert.NoError(t, err)
	ext := CreateEDDSAExtendedPrivateKey(privKey, cc)

	assert.Equal(t, vector.extPrivKey, ext.String())
	assert.Equal(t, vector.extPubKey, ext.PublicKey().String())

	extPubKey := CreateEDDSAExtendedPublicKey(privKey.PubKey(), cc)
	assert.Equal(t, vector.extPubKey, extPubKey.String())

	var extPrivKey CKDKey = ext
	// Iterate over the entire child chain and test the given keys
	for _, testChildKey := range vector.children {
		// Get the private key at the given key tree path
		extPrivKey, err = extPrivKey.NewChildKey(testChildKey.pathFragment)
		assert.NoError(t, err)
		assert.Equal(t, testChildKey.hexPrivKey, utils.Encode(extPrivKey.GetKey()))
		assert.Equal(t, testChildKey.hexPubkey, utils.Encode(extPrivKey.PublicKey().GetKey()))
		assert.Equal(t, testChildKey.chaincode, utils.Encode(extPrivKey.GetChainCode()))
		assert.Equal(t, testChildKey.extPrivKey, extPrivKey.String())
		assert.Equal(t, testChildKey.extPubKey, extPrivKey.PublicKey().String())

		// Serialize and deserialize both keys and ensure they're the same
		assertKeySerialization(t, extPrivKey, testChildKey.extPrivKey)
		assertKeySerialization(t, extPrivKey.PublicKey(), testChildKey.extPubKey)
	}
}

func testPublicKey(t *testing.T, vector testKey) {
	t.Helper()
	cc, err := utils.Decode(vector.chaincode)
	assert.NoError(t, err)

	pubBytes, err := utils.Decode(vector.hexPubkey)
	assert.NoError(t, err)

	pub, err := DecompressEDDSAPubKey(pubBytes)
	assert.NoError(t, err)

	ext := CreateEDDSAExtendedPublicKey(pub, cc)
	assert.Equal(t, vector.extPubKey, ext.String())

	var extPubKey CKDKey = ext
	// Iterate over the entire child chain and test the given keys
	for _, testChildKey := range vector.children {
		// Get the private key at the given key tree path
		extPubKey, err = extPubKey.NewChildKey(testChildKey.pathFragment)
		assert.NoError(t, err)
		assert.Equal(t, testChildKey.hexPubkey, utils.Encode(extPubKey.GetKey()))
		assert.Equal(t, testChildKey.chaincode, utils.Encode(extPubKey.GetChainCode()))
		assert.Equal(t, testChildKey.extPubKey, extPubKey.String())

		assertKeySerialization(t, extPubKey.PublicKey(), testChildKey.extPubKey)
	}
}

func assertKeySerialization(t *testing.T, key CKDKey, knownBase58 string) {
	t.Helper()
	serializedBase58 := key.B58Serialize()
	assert.Equal(t, knownBase58, serializedBase58)

	unserializedBase58, err := B58Deserialize(serializedBase58)
	assert.NoError(t, err)
	assert.Equal(t, key, unserializedBase58)
}
