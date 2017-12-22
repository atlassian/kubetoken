deps:
	@glide i

build:
	# Build kubetokend
	@go build -o dist/kubetokend ./cmd/kubetokend
	# Build kubetoken cli
	@go build -o dist/kubetoken ./cmd/kubetoken
