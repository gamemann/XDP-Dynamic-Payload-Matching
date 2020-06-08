CC = clang

objects += src/loader.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o

LDFLAGS += -lelf -lz

all: loader methodone methodtwo methodthree methodfour
loader: libbpf $(objects)
	clang $(LDFLAGS) -o loader $(libbpf_static_objects) $(objects)
methodone: src/xdp_methodone.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_methodone.c -o src/xdp_methodone.bc
	llc -march=bpf -filetype=obj src/xdp_methodone.bc -o src/xdp_methodone.o
methodtwo: src/xdp_methodtwo.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_methodtwo.c -o src/xdp_methodtwo.bc
	llc -march=bpf -filetype=obj src/xdp_methodtwo.bc -o src/xdp_methodtwo.o
methodthree: src/xdp_methodthree.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_methodthree.c -o src/xdp_methodthree.bc
	llc -march=bpf -filetype=obj src/xdp_methodthree.bc -o src/xdp_methodthree.o
methodfour: src/xdp_methodfour.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdp_methodfour.c -o src/xdp_methodfour.bc
	llc -march=bpf -filetype=obj src/xdp_methodfour.bc -o src/xdp_methodfour.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f loader
.PHONY: libbpf all
.DEFAULT: all