build:asset/rootCa.pem asset/rootKey.pem fmt vet
	go build -o build/icert github.com/lyp256/icert/cmd

asset/rootCa.pem:
	go generate asset/mkca.go

asset/rootKey.pem:
	go generate asset/mkca.go

fmt:
	go list ./... |grep -v vendor |xargs go fmt

vet:
	go list ./... |grep -v vendor |xargs go vet

pretty: fmt vet
