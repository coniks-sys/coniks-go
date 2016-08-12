# CONIKS Server implementation in Golang

## Usage
Generate new config file with proper format
```
go run keyserver/coniksserver/main.go -genconfig
```

Generate new key pair for VRF and signing
``` 
go run utils/keygen/mkkey.go -vrf -signing
```

Generate a private key for secure connection (TLS)
```
openssl ecparam -genkey -name prime256v1 -out server.key
```

Generation of self-signed(x509) public key (PEM-encodings `.pem`) based on the private (`.key`)
```
openssl req -new -x509 -sha256 -key server.key -out server.pem -days 3650
```

Run the server
```
go run keyserver/coniksserver/main.go
```

## Disclaimer
Please keep in mind that this CONIKS server implementation is under active development. The repository may contain experimental features that aren't fully tested.
