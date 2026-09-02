CLANG ?= clang
BPFTOOL ?= bpftool
BPF_HEADERS = /usr/include
ARCH := $(shell uname -m)

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I$(BPF_HEADERS) -I. -Wall -Wno-unused-variable

BPF_PROGS = capability.bpf.o filesystem.bpf.o network.bpf.o

all: vmlinux.h $(BPF_PROGS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

%.bpf.o: %.bpf.c common.bpf.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.bpf.o vmlinux.h
