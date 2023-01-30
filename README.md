# chi-go-srp

Secure Remote Password For Go Client And Server.

## install

```
go get github.com/langwan/chi-go-srp
```

## js client

`@chihuo/srpclient` is js client only(support node/browserify), `chi_go_srp` is go server or client.

```
yarn add @chihuo/srpclient
```

link:

[Secure Remote Password Wiki](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
[Secure Remote Password](http://srp.stanford.edu/)

fork:

[go-srp](https://github.com/Kong/go-srp)

chi_go_srp is improved and optimized for go-srp

## example

```go

var err error

params, err := GetParams(2048)
if err != nil {
	panic(err)
}

// register send  salt, username, verifier to server
// salt, username, verifier save to database
salt, err := GenKey()
if err != nil {
	panic(err)
}
verifier := ComputeVerifier(params, salt, []byte(username), []byte(password))

// login 1 client send public key (computeA) to server
secretClient, err := GenKey()
if err != nil {
	panic(err)
}

client := NewClient(params, secretClient)
computeA := client.ComputeA()

// login 2 server send public key (computeB), salt to client
// verifier from database
secretServer, err := GenKey()
if err != nil {
	panic(err)
}
server := NewServer(params, verifier, secretServer)
computeB := server.ComputeB()

// login 3 client send match key (m1) to server
// salt from server response
client.setPrivateKey(salt, []byte(username), []byte(password))
client.SetB(computeB)
m1, err := client.ComputeM1()
if err != nil {
	panic(err)
}

// login 4 server check m1, if ok return m2 to client
server.SetA(computeA)
m2, ok := server.CheckM1(m1)
if !ok {
	panic("check m1 error")
}

// login 5 client check m2 （optional step)
ok = client.CheckM2(m2)
if !ok {
	panic("check m2 error")
}

```
