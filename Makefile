.PHONY: tool test clean

tool:
	go build -o build/cobo-mpc-recovery-tool main.go

test:
	go test -v ./...

clean:
	go clean
	@rm -r build
