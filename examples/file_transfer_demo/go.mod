module github.com/bbockelm/golang-htcondor/examples/file_transfer_demo

go 1.24.0

replace github.com/bbockelm/golang-htcondor => ../..

require (
	github.com/PelicanPlatform/classad v0.0.4
	github.com/bbockelm/cedar v0.0.22
	github.com/bbockelm/golang-htcondor v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
