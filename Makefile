# Makefile
# Run tests and such
# By J. Stuart McMurray
# Created 20230811
# Last Modified 20230811

# Most users of this library won't need this file.

check:
	go test     ./...
	go vet      ./...
	staticcheck ./...
