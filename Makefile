deps:
	@glide i

build-kubetokend:
	# Build kubetokend
	@go build -o dist/kubetokend ./cmd/kubetokend

build-kubetoken:
	# Build kubetoken cli
	@go build -o dist/kubetoken ./cmd/kubetoken
