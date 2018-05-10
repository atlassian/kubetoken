.PHONY: build setup test test-race

build:
	CGO_ENABLED=1 go build -o kubetoken cmd/kubetoken/*.go
	CGO_ENABLED=1 go build -o kubetokend cmd/kubetokend/*.go

setup:
	dep ensure

test:
	go test ./... -cover

test-race:
	go test ./... -cover -race
