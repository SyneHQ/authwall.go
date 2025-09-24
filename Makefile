run-wall:
	export $$(cat .env | xargs) && go run main.go