setup:
	@go mod tidy
	@go mod download

run: setup
	@templ generate
	@go run cmd/main.go

.PHONY: setup run
