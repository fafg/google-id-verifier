
build:
	go build .

release:
	@ chmod +x ./ci/release.sh
	@ ./ci/release.sh ${PWD}/main/version.go
