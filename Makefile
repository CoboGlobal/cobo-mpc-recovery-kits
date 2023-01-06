.PHONY: recovery-tool clean

recovery-tool:
	go build -o build/cobo-mpc-recovery-tool main.go

clean:
	go clean
	@rm -r build
