CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
CPPFLAGS += -D_DEFAULT_SOURCE -Isrc $(shell $(PKG_CONFIG) --cflags libsodium)
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS += $(shell $(PKG_CONFIG) --libs libsodium)
CORE = src/protocol.c src/keys.c src/replay.c
.PHONY: all test bench sanitize clean check
all: metadata-proxy tools/udp-traffic
metadata-proxy: src/main.c src/bench.c $(CORE) src/mdpx.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ src/main.c src/bench.c $(CORE) $(LDLIBS)
tests/test_protocol: tests/test_protocol.c $(CORE) src/mdpx.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_protocol.c $(CORE) $(LDLIBS)
tools/udp-traffic: tools/udp-traffic.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)
test: all tests/test_protocol
	./tests/test_protocol
	python3 tests/fixture.py
	python3 tests/integration.py
check: test
bench: all
	./metadata-proxy bench
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-fsanitize=address,undefined -no-pie' test
clean:
	rm -f metadata-proxy tests/test_protocol tools/udp-traffic wireshark/mdpx.so

.PHONY: wireshark test-wireshark
wireshark:
	$(MAKE) -C wireshark
test-wireshark:
	$(MAKE) -C wireshark test
