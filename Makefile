.PHONY: build setup test test-race

build:
	go build -o kubetoken cmd/kubetoken/*.go
	go build -o kubetokend cmd/kubetokend/*.go

setup:
	dep ensure

test:
	go test ./... -cover

test-race:
	go test ./... -cover -race
