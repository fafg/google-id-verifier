
build:
	go build .

release:
	@ chmod +x ./ci/release.sh
	@ ./ci/release.sh ${PWD}/version.go
