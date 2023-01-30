package chi_go_srp

import (
	"bytes"
	"errors"
	"math/big"
)

type Client struct {
	Params     *Params
	Multiplier *big.Int
	Secret     *big.Int
	A          *big.Int
	X          *big.Int
	u          *big.Int
	s          *big.Int
	K          []byte
	M1         []byte
	M2         []byte
}

func NewClient(params *Params, secret []byte) *Client {
	multiplier := getMultiplier(params)
	client := Client{Params: params, Secret: intFromBytes(secret), Multiplier: multiplier}
	Ab := getA(params, client.Secret)
	client.A = intFromBytes(Ab)
	return &client
}

func (c *Client) setPrivateKey(salt, identity, password []byte) {
	x := getx(c.Params, salt, identity, password)
	c.X = x
}

func (c *Client) ComputeA() []byte {
	return intToBytes(c.A)
}

func (c *Client) SetB(Bb []byte) {
	B := intFromBytes(Bb)
	u := getu(c.Params, c.A, B)
	S := clientGetS(c.Params, c.Multiplier, c.X, c.Secret, B, u)

	c.K = getK(c.Params, S)
	c.M1 = getM1(c.Params, intToBytes(c.A), Bb, S)
	c.M2 = getM2(c.Params, intToBytes(c.A), c.M1, c.K)

	c.u = u               // Only for tests
	c.s = intFromBytes(S) // Only for tests
}

func (c *Client) ComputeM1() ([]byte, error) {
	if c.M1 == nil {
		return nil, errors.New("m1 is nil")
	}
	return c.M1, nil
}

func (c *Client) CheckM2(M2 []byte) bool {
	if !bytes.Equal(c.M2, M2) {
		return false
	} else {
		return true
	}
}

func ComputeVerifier(params *Params, salt, identity, password []byte) []byte {
	x := getx(params, salt, identity, password)
	vNum := new(big.Int)
	vNum.Exp(params.G, x, params.N)
	return padToN(vNum, params)
}

func clientGetS(params *Params, k, x, a, B, u *big.Int) []byte {
	BLessThan0 := B.Cmp(big.NewInt(0)) <= 0
	NLessThanB := params.N.Cmp(B) <= 0
	if BLessThan0 || NLessThanB {
		panic("invalid server-supplied 'B', must be 1..N-1")
	}

	result1 := new(big.Int)
	result1.Exp(params.G, x, params.N)

	result2 := new(big.Int)
	result2.Mul(k, result1)

	result3 := new(big.Int)
	result3.Sub(B, result2)

	result4 := new(big.Int)
	result4.Mul(u, x)

	result5 := new(big.Int)
	result5.Add(a, result4)

	result6 := new(big.Int)
	result6.Exp(result3, result5, params.N)

	result7 := new(big.Int)
	result7.Mod(result6, params.N)

	return padToN(result7, params)
}
