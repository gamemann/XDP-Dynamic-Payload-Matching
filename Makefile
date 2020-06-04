CC = clang

objects += src/loader.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o

LDFLAGS += -lelf -lz

all: loader xdpprog
loader: libbpf $(objects)
	clang $(LDFLAGS) -o loader $(libbpf_static_objects) $(objects)
xdpprog: src/xdp_prog.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_prog.c -o src/xdp_prog.bc
	llc -march=bpf -filetype=obj src/xdp_prog.bc -o src/xdp_prog.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f loader
.PHONY: libbpf all
.DEFAULT: all