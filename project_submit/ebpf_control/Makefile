# Makefile - 构建 XDP BPF 对象、生成 skeleton、编译用户态 loader

CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX := /sys/kernel/btf/vmlinux
CFLAGS := -g -O2 -Wall -Wextra -I. -I/usr/include/$(shell $(CC) -dumpmachine)
LDFLAGS := -lbpf -lelf -lz

BPF_SRC := src/xdp_blacklist.bpf.c
BPF_OBJ := xdp_blacklist.bpf.o
SKEL := xdp_blacklist.skel.h
LOADER_SRC := src/loader.c
LOADER_BIN := loader

.PHONY: all clean check-env run

all: $(LOADER_BIN)

check-env:
	@echo "== 环境检查 =="
	@uname -r
	@$(CLANG) --version | head -n 1
	@$(BPFTOOL) version || true
	@pkg-config --modversion libbpf || true
	@test -r $(VMLINUX) || (echo "缺少 $(VMLINUX)，请确认内核开启 BTF" && exit 1)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell $(CC) -dumpmachine) \
		-c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER_BIN): $(LOADER_SRC) $(SKEL)
	$(CC) $(CFLAGS) -o $@ $(LOADER_SRC) $(LDFLAGS)

run: all
	sudo ./$(LOADER_BIN) -c conf/xdp_loader.conf

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(LOADER_BIN)
