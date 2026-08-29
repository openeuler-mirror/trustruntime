CLANG ?= clang
BPF_HEADERS = /usr/include
ARCH := $(shell uname -m)

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I$(BPF_HEADERS) -Wall -Wno-unused-variable

BPF_PROGS = capability.bpf.o filesystem.bpf.o network.bpf.o

all: $(BPF_PROGS)

%.bpf.o: %.bpf.c common.bpf.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.bpf.o
