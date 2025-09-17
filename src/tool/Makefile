CLANG ?= clang
BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CC ?= gcc

INCDIR := ../../src/include
BPFDIR := ../../src/bpf
BINDIR := ../../bin

TOOL_SRCS := debug_cgroup_pbf.c
TOOL_BPF_SRCS := trace_cgroup_progs.bpf.c

TOOL_BINS := $(addprefix $(BINDIR)/, $(TOOL_SRCS:.c=))
TOOL_OBJS := $(addprefix $(BINDIR)/, $(TOOL_SRCS:.c=.o))
TOOL_BPF_OBJS := $(addprefix $(BINDIR)/, $(TOOL_BPF_SRCS:.c=.o))

CFLAGS := -O2 -g -Wall -fPIE
PKG_CONFIG_PATH ?= /usr/lib64/pkgconfig
PKG_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags libbpf 2>/dev/null)
PKG_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs libbpf 2>/dev/null)

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

.PHONY: all clean bpf

all: $(TOOL_BINS) $(TOOL_BPF_OBJS)

$(BINDIR)/%: $(BINDIR)/%.o | $(BINDIR)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -I$(INCDIR) $< -o $@ $(PKG_LIBS) -pie

$(BINDIR)/%.o: %.c | $(BINDIR)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -I$(INCDIR) -c $< -o $@

$(BINDIR)/trace_cgroup_progs.bpf.o: trace_cgroup_progs.bpf.c | $(BINDIR)
	$(BPF_CLANG) -g -O2 -target bpf $(ARCH_FLAG) -I/usr/include/bpf -I$(BPFDIR) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(TOOL_BINS) $(TOOL_OBJS) $(TOOL_BPF_OBJS)


