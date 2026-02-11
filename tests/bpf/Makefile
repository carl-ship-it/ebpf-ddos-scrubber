# BPF Test Harness Build

CC      := gcc
CFLAGS  := -Wall -O2
LDFLAGS := -lbpf -lelf -lz

BPF_OBJ := ../../build/obj/xdp_ddos_scrubber.o

.PHONY: all test clean

all: test_xdp

test_xdp: test_xdp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: test_xdp $(BPF_OBJ)
	@echo "=== Running BPF XDP tests ==="
	sudo ./test_xdp $(BPF_OBJ)

clean:
	rm -f test_xdp
