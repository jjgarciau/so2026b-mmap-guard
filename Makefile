# Makefile - Entrega 3 SO2026B: mmap_guard (eBPF LSM)
#
#   make          compila el programa eBPF, el loader y las pruebas
#   make test     ejecuta las pruebas de ataque/defensa (pide sudo)
#   make race     ejecuta las pruebas de condición de carrera (pide sudo)
#   make bench    mide el overhead de la defensa (pide sudo)
#   make clean    borra artefactos
#
# Requisitos (Ubuntu 24.04 / WSL2): clang, llvm, libbpf-dev, libelf-dev,
# zlib1g-dev, bpftool y un kernel con CONFIG_BPF_LSM=y, BTF y "bpf" en lsm=.

BUILD   := build
BIN     := mmap_guard
PROBE   := tests/mmap_probe
RACE    := tests/race_cow
BENCH   := bench/bench_mmap

CLANG   ?= clang
CC      ?= gcc
# bpftool: se prefiere el binario real de linux-tools (el wrapper de
# /usr/sbin/bpftool no reconoce el kernel de WSL)
BPFTOOL ?= $(or $(shell ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | sort -V | tail -1),$(shell command -v bpftool 2>/dev/null))

ARCH    := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

# Lado usuario: compilación estricta (clean build = cero warnings)
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Werror
LDLIBS  := -lbpf -lelf -lz

# Lado BPF: igual de estricto, salvo -Wunused-parameter. La macro BPF_PROG de
# libbpf genera un parámetro 'ctx' que no siempre se usa, y los hooks reciben
# argumentos (p. ej. reqprot) que la política no necesita.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wall -Wextra -Wno-unused-parameter -Werror

.PHONY: all test race bench clean check-env

all: $(BIN) $(PROBE) $(RACE) $(BENCH)

check-env:
	@test -n "$(BPFTOOL)" || { echo "ERROR: no se encontró bpftool"; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "ERROR: el kernel no expone BTF"; exit 1; }

$(BUILD):
	mkdir -p $@

# 1) Tipos del kernel EN EJECUCIÓN, extraídos de su BTF (CO-RE)
$(BUILD)/vmlinux.h: | $(BUILD) check-env
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2) Programa eBPF -> objeto BPF
$(BUILD)/mmap_guard.bpf.o: src/bpf/mmap_guard.bpf.c src/common.h $(BUILD)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I$(BUILD) -c $< -o $@

# 3) Skeleton: cabecera C que embebe el objeto BPF y expone sus mapas/programas
$(BUILD)/mmap_guard.skel.h: $(BUILD)/mmap_guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 4) Loader en espacio de usuario
$(BIN): src/loader/mmap_guard.c src/loader/policy.c src/loader/policy.h \
        src/common.h $(BUILD)/mmap_guard.skel.h
	$(CC) $(CFLAGS) -I$(BUILD) -o $@ src/loader/mmap_guard.c src/loader/policy.c $(LDLIBS)

# Programas de prueba y benchmark (no dependen de libbpf)
$(PROBE): tests/mmap_probe.c
	$(CC) $(CFLAGS) -o $@ $<

$(RACE): tests/race_cow.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

$(BENCH): bench/bench_mmap.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	sudo bash tests/run_tests.sh

race: all
	sudo bash tests/run_race.sh

bench: all
	sudo bash bench/run_bench.sh

clean:
	rm -rf $(BUILD) $(BIN) $(PROBE) $(RACE) $(BENCH)
