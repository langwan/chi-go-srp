package chi_go_srp

import (
	"bytes"
	"math/big"
)

type Server struct {
	Params   *Params
	Verifier *big.Int
	Secret   *big.Int
	B        *big.Int
	M1       []byte
	M2       []byte
	K        []byte
	u        *big.Int
	s        *big.Int
}

func NewServer(params *Params, verifier []byte, secret []byte) *Server {
	multiplier := getMultiplier(params)
	v := intFromBytes(verifier)
	se := intFromBytes(secret)
	Bb := getB(params, multiplier, v, se)
	B := intFromBytes(Bb)
	return &Server{
		Params:   params,
		Secret:   se,
		Verifier: v,
		B:        B,
	}
}

func (s *Server) ComputeB() []byte {
	return intToBytes(s.B)
}

func (s *Server) SetA(A []byte) {
	AInt := intFromBytes(A)
	U := getu(s.Params, AInt, s.B)
	S := serverGetS(s.Params, s.Verifier, AInt, s.Secret, U)

	s.K = getK(s.Params, S)
	s.M1 = getM1(s.Params, A, intToBytes(s.B), S)
	s.M2 = getM2(s.Params, A, s.M1, s.K)

	s.u = U               // only for tests
	s.s = intFromBytes(S) // only for tests
}

func (s *Server) CheckM1(M1 []byte) ([]byte, bool) {
	if !bytes.Equal(s.M1, M1) {
		return nil, false
	} else {
		return s.M2, true
	}
}

func getB(params *Params, multiplier, V, b *big.Int) []byte {
	gModPowB := new(big.Int)
	gModPowB.Exp(params.G, b, params.N)

	kMulV := new(big.Int)
	kMulV.Mul(multiplier, V)

	leftSide := new(big.Int)
	leftSide.Add(kMulV, gModPowB)

	final := new(big.Int)
	final.Mod(leftSide, params.N)

	return padToN(final, params)
}

func serverGetS(params *Params, V, A, S2, U *big.Int) []byte {
	ALessThan0 := A.Cmp(big.NewInt(0)) <= 0
	NLessThanA := params.N.Cmp(A) <= 0
	if ALessThan0 || NLessThanA {
		panic("invalid client-supplied 'A', must be 1..N-1")
	}

	result1 := new(big.Int)
	result1.Exp(V, U, params.N)

	result2 := new(big.Int)
	result2.Mul(A, result1)

	result3 := new(big.Int)
	result3.Exp(result2, S2, params.N)

	result4 := new(big.Int)
	result4.Mod(result3, params.N)

	return padToN(result4, params)
}
