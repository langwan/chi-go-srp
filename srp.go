package chi_go_srp

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math/big"
	"regexp"
)

type Params struct {
	G           *big.Int
	N           *big.Int
	Hash        crypto.Hash
	NLengthBits int
}

var paramsGroup map[int]*Params

func init() {
	paramsGroup = make(map[int]*Params)

	paramsGroup[1024] = newParams(2, 1024, crypto.SHA1, `
		EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
		9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
		8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
		7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
		FD5138FE 8376435B 9FC61D2F C0EB06E3`)

	paramsGroup[1536] = newParams(2, 1536, crypto.SHA1, `
		9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
		4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
		80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
		E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
		6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
		F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
		8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
	`)

	paramsGroup[2048] = newParams(2, 2048, crypto.SHA256, `
		AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
		3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
		CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
		D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
		7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
		436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
		5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
		03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
		94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
		9E4AFF73
	`)

	paramsGroup[4096] = newParams(5, 4096, crypto.SHA256, `
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
		8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
		302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
		A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
		49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
		FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
		670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
		180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
		3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
		04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
		B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
		1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
		BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
		E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
		99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
		04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
		233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
		D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
		FFFFFFFF FFFFFFFF
	`)
}

func newParams(G int64, nBitLength int, hash crypto.Hash, NHex string) *Params {
	p := Params{
		G:           big.NewInt(G),
		N:           new(big.Int),
		NLengthBits: nBitLength,
		Hash:        hash,
	}

	b := bytesFromHexString(NHex)
	p.N.SetBytes(b)
	return &p
}

func GetParams(bits int) (*Params, error) {
	if params, ok := paramsGroup[bits]; ok {
		return params, nil
	} else {
		return nil, errors.New("Params not find")
	}
}

func bytesFromHexString(s string) []byte {
	re, _ := regexp.Compile("[^0-9a-fA-F]")
	h := re.ReplaceAll([]byte(s), []byte(""))
	b, _ := hex.DecodeString(string(h))
	return b
}

func GenKey() ([]byte, error) {
	bytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func getx(params *Params, salt, I, P []byte) *big.Int {
	var ipBytes []byte
	ipBytes = append(ipBytes, I...)
	ipBytes = append(ipBytes, []byte(":")...)
	ipBytes = append(ipBytes, P...)

	hashIP := params.Hash.New()
	hashIP.Write(ipBytes)

	hashX := params.Hash.New()
	hashX.Write(salt)
	hashX.Write(hashToBytes(hashIP))

	return hashToInt(hashX)
}

func hashToBytes(h hash.Hash) []byte {
	return h.Sum(nil)
}

func hashToInt(h hash.Hash) *big.Int {
	U := new(big.Int)
	U.SetBytes(hashToBytes(h))
	return U
}

func padToN(number *big.Int, params *Params) []byte {
	return padTo(number.Bytes(), params.NLengthBits/8)
}

func padTo(bytes []byte, length int) []byte {
	paddingLength := length - len(bytes)
	padding := make([]byte, paddingLength, paddingLength)
	return append(padding, bytes...)
}

func intFromBytes(bytes []byte) *big.Int {
	i := new(big.Int)
	i.SetBytes(bytes)
	return i
}
func intToBytes(i *big.Int) []byte {
	return i.Bytes()
}

func getA(params *Params, a *big.Int) []byte {
	ANum := new(big.Int)
	ANum.Exp(params.G, a, params.N)
	return padToN(ANum, params)
}

func getMultiplier(params *Params) *big.Int {
	hashK := params.Hash.New()
	hashK.Write(padToN(params.N, params))
	hashK.Write(padToN(params.G, params))
	return hashToInt(hashK)
}
func getu(params *Params, A, B *big.Int) *big.Int {
	hashU := params.Hash.New()
	hashU.Write(A.Bytes())
	hashU.Write(B.Bytes())

	return hashToInt(hashU)
}

func getK(params *Params, S []byte) []byte {
	hashK := params.Hash.New()
	hashK.Write(S)
	return hashToBytes(hashK)
}

func getM1(params *Params, A, B, S []byte) []byte {
	hashM1 := params.Hash.New()
	hashM1.Write(A)
	hashM1.Write(B)
	hashM1.Write(S)
	return hashToBytes(hashM1)
}

func getM2(params *Params, A, M, K []byte) []byte {
	hashM1 := params.Hash.New()
	hashM1.Write(A)
	hashM1.Write(M)
	hashM1.Write(K)
	return hashToBytes(hashM1)
}
