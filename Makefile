.PHONY: recovery-tool test clean

recovery-tool:
	go build -o build/cobo-mpc-recovery-tool main.go

test:
	go test -v ./...

clean:
	go clean
	@rm -r build
