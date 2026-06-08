.PHONY: build install clean

BINARY_NAME=tuncli
BUILD_DIR=build

build:
	go build -tags with_gvisor,with_dhcp,with_wireguard,with_utls,with_clash_api,with_quic -o $(BUILD_DIR)/$(BINARY_NAME) main.go

install: build
	install -Dm755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)
