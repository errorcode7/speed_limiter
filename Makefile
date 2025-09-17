BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CC ?= gcc
## 目录结构
INCDIR := src/include
TOOLDIR := src/limiter
BPFDIR := src/bpf
BINDIR := bin
TOOLSDIR := src/tool

BPFOBJ := $(BINDIR)/limiter.bpf.o
USEROBJ := $(BINDIR)/limiter

# 源文件列表
TOOL_SOURCES := $(TOOLDIR)/main.c $(TOOLDIR)/utils.c $(TOOLDIR)/cgroup.c $(TOOLDIR)/bpf.c $(TOOLDIR)/managed.c $(TOOLDIR)/cli.c
TOOL_OBJECTS := $(TOOL_SOURCES:$(TOOLDIR)/%.c=$(BINDIR)/%.o)

CFLAGS := -O2 -g -Wall -fPIE
PKG_CONFIG_PATH ?= /usr/lib64/pkgconfig
PKG_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags libbpf 2>/dev/null)
PKG_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs libbpf 2>/dev/null)

# 安装前缀/目的根，供 Debian 或手工安装使用
PREFIX ?= /usr
DESTDIR ?=

# 自动探测架构并映射到 __TARGET_ARCH_*
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  ARCH_FLAG := -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
  ARCH_FLAG := -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
  ARCH_FLAG := -D__TARGET_ARCH_arm64
else
  ARCH_FLAG := -D__TARGET_ARCH_x86
endif

all: tool tools

tool: $(USEROBJ)

.PHONY: tools
tools:
	$(MAKE) -C $(TOOLSDIR)

.PHONY: bpf gen-vmlinux
bpf: gen-vmlinux $(BPFOBJ)
	@echo "BPF 对象已构建: $(BPFOBJ)"

gen-vmlinux:
	@if command -v bpftool >/dev/null 2>&1; then \
		echo "[gen] vmlinux.h (force)"; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPFDIR)/vmlinux.h; \
	else \
		echo "错误: 未找到 bpftool，无法生成 $(BPFDIR)/vmlinux.h；请安装 bpftool 或使用 deb 安装时生成"; \
		exit 1; \
	fi

$(BPFOBJ): $(BPFDIR)/limiter.bpf.c $(INCDIR)/limiter.h $(BPFDIR)/vmlinux.h | $(BINDIR)
	$(BPF_CLANG)  -g -O2 -target bpf $(ARCH_FLAG) -I/usr/include/bpf -I$(INCDIR) -I$(BPFDIR) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

# 保留占位目标
$(BPFDIR)/vmlinux.h:
	@echo "提示: 请运行 make bpf（将自动生成 $(BPFDIR)/vmlinux.h）"

$(USEROBJ): $(TOOL_OBJECTS) | $(BINDIR)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -I$(INCDIR) -I$(TOOLDIR) $(TOOL_OBJECTS) -o $(USEROBJ) $(PKG_LIBS) -pie

$(BINDIR)/%.o: $(TOOLDIR)/%.c | $(BINDIR)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -I$(INCDIR) -I$(TOOLDIR) -c $< -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(BPFOBJ) $(USEROBJ) $(TOOL_OBJECTS)
	$(MAKE) -C src/tool clean || true

.PHONY: install
install: $(USEROBJ)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(USEROBJ) $(DESTDIR)$(PREFIX)/bin/limiter
	# 安装 BPF 源码与头文件
	install -d $(DESTDIR)$(PREFIX)/share/speed_limiter
	install -m 0644 $(BPFDIR)/limiter.bpf.c $(DESTDIR)$(PREFIX)/share/speed_limiter/limiter.bpf.c
	install -m 0644 $(INCDIR)/limiter.h $(DESTDIR)$(PREFIX)/share/speed_limiter/limiter.h
	install -m 0644 Makefile $(DESTDIR)$(PREFIX)/share/speed_limiter/Makefile.src

.PHONY: all clean

