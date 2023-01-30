package chi_go_srp

import "testing"

const (
	username      = "chihuo"
	password      = "123456"
	loginPassword = "000000"
)

func TestSrp(t *testing.T) {
	var err error
	defer func() {
		if err != nil {
			t.Error(err)
		}
	}()

	params, err := GetParams(2048)
	if err != nil {
		return
	}
	t.Log("Params", params)

	// register
	salt, err := GenKey()
	if err != nil {
		return
	}
	t.Log("salt", salt)
	verifier := ComputeVerifier(params, salt, []byte(username), []byte(password))
	t.Log("verifier", verifier)

	// login client send public key
	secretClient, err := GenKey()
	if err != nil {
		return
	}
	t.Log("secretClient", secretClient)
	// gen client public key
	client := NewClient(params, secretClient)
	computeA := client.ComputeA()
	t.Log("computeA", computeA)

	// login server send public key
	secretServer, err := GenKey()
	if err != nil {
		return
	}
	t.Log("secretServer", secretServer)
	server := NewServer(params, verifier, secretServer)
	computeB := server.ComputeB()
	t.Log("computeB", computeB)

	// login client send match 1
	client.setPrivateKey(salt, []byte(username), []byte(password))
	client.SetB(computeB)
	m1, err := client.ComputeM1()
	if err != nil {
		return
	}
	t.Log("m1", m1)

	// login server check m1
	server.SetA(computeA)
	m2, ok := server.CheckM1(m1)
	if !ok {
		t.Error("check m1 error")
		return
	}
	t.Log("m2", m2)

	// login client check m2
	ok = client.CheckM2(m2)
	if !ok {
		t.Error("check m2 error")
		return
	}
}
