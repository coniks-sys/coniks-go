# CONIKS Server implementation in Golang

## Usage
Generate new config file with proper format
```
go run utils/configen/mkconfig.go
```

Generate new key pair for signing
``` 
go run utils/keygen/mkkey.go 
```

Run the server
```
go run keyserver/coniksserver/main.go
```

## Disclaimer
Please keep in mind that this CONIKS server implementation is under active development. The repository may contain experimental features that aren't fully tested.
