#!/usr/bin/env bash
# run_bench.sh - Mide el overhead de mmap_guard.
#
# Escenarios:
#   S0 sin_guard            sin defensa (línea base)
#   S1 guard_no_protegido   defensa activa, archivo SIN política (lookup que falla)
#   S2 guard_protegido      defensa activa, archivo CON política, acceso permitido
#   S3 guard_protegido_log  igual que S2 pero registrando cada acceso (-v): peor caso
#
# Herramientas:
#   - bench_mmap (tiempos con clock_gettime, mediana de REPS repeticiones)
#   - perf stat  (fallos de página, cambios de contexto, task-clock)
#   - strace -c  (distribución del tiempo por syscall)
#   - ftrace     (function_graph: duración de security_mmap_file / security_file_mprotect)
#
# Uso: sudo bash bench/run_bench.sh [repeticiones]   (por defecto 5)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GUARD="$ROOT/mmap_guard"
BENCH="$ROOT/bench/bench_mmap"
OUT="$ROOT/results/bench"
REPS=${1:-5}

N_MMAP=200000
N_MPROT=200000
N_FAULT=100
N_READ=100
FILE_MB=16

[ "$EUID" -eq 0 ] || { echo "Ejecutar con sudo." >&2; exit 1; }
[ -x "$GUARD" ] || { echo "Compile primero con: make" >&2; exit 1; }
[ -r /sys/kernel/security/lsm ] || mount -t securityfs securityfs /sys/kernel/security

if [ ! -x "$BENCH" ] || [ "$ROOT/bench/bench_mmap.c" -nt "$BENCH" ]; then
	gcc -O2 -g -std=gnu11 -Wall -Wextra -Werror -o "$BENCH" "$ROOT/bench/bench_mmap.c" || exit 1
fi

mkdir -p "$OUT"
RAW="$OUT/raw.csv"
SUMMARY="$OUT/summary.csv"
echo "escenario,rep,prueba,iteraciones,total_ns,ns_por_op,unidad,fallos_menores,fallos_mayores,checksum" > "$RAW"

WORK=$(mktemp -d /tmp/mmap_guard_bench.XXXXXX)
UNPROT="$WORK/no_protegido.dat"
PROT="$WORK/protegido.dat"
POLICY="$WORK/policy.conf"
head -c "${FILE_MB}M" /dev/urandom > "$UNPROT"
head -c "${FILE_MB}M" /dev/urandom > "$PROT"
echo "$PROT - write,exec" > "$POLICY"

PIN=""
if command -v taskset >/dev/null; then   # fijar CPU: menos ruido
	PIN="taskset -c $(( $(nproc) > 1 ? 1 : 0 ))"
fi

GPID=""
TRACEFS=""
cleanup() {
	[ -n "$GPID" ] && kill -INT "$GPID" 2>/dev/null && wait "$GPID" 2>/dev/null
	if [ -n "$TRACEFS" ]; then
		echo 0 > "$TRACEFS/tracing_on"
		echo nop > "$TRACEFS/current_tracer"
		echo > "$TRACEFS/set_graph_function"
		echo > "$TRACEFS/set_ftrace_pid"
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

start_guard() {  # $1 = etiqueta, resto = opciones
	local tag=$1; shift
	"$GUARD" -c "$POLICY" -s "$@" > "$OUT/guard_$tag.log" 2>&1 &
	GPID=$!
	for _ in $(seq 1 50); do
		grep -q "activo" "$OUT/guard_$tag.log" 2>/dev/null && return 0
		kill -0 "$GPID" 2>/dev/null || break
		sleep 0.2
	done
	cat "$OUT/guard_$tag.log" >&2
	exit 1
}
stop_guard() { kill -INT "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null; GPID=""; }

run_suite() {  # escenario archivo
	local sc=$1 f=$2
	echo "  [$sc] $REPS repeticiones..."
	for rep in $(seq 1 "$REPS"); do
		for t in "mmap $N_MMAP" "mprotect $N_MPROT" "fault $N_FAULT" "read $N_READ" "mmapread $N_READ"; do
			# shellcheck disable=SC2086
			set -- $t
			echo "$sc,$rep,$($PIN "$BENCH" "$1" "$f" "$2")" >> "$RAW"
		done
	done
}

run_perf() {  # escenario archivo
	command -v perf >/dev/null || return 0
	perf stat -x, -o "$OUT/perf_$1.csv" \
		-e page-faults,minor-faults,major-faults,context-switches,cpu-migrations,task-clock \
		$PIN "$BENCH" fault "$2" "$N_FAULT" > /dev/null 2>&1 \
		|| echo "  (perf stat no disponible en este kernel)"
}

run_strace() {  # escenario archivo
	command -v strace >/dev/null || return 0
	strace -c -o "$OUT/strace_$1.txt" "$BENCH" mmap "$2" 20000 > /dev/null 2>&1
}

setup_ftrace() {
	local t=/sys/kernel/tracing
	[ -d "$t/events" ] || mount -t tracefs nodev "$t" 2>/dev/null
	if [ -w "$t/current_tracer" ] && grep -qw function_graph "$t/available_tracers"; then
		TRACEFS=$t
	else
		echo "  (ftrace function_graph no disponible; se omite)"
	fi
}

run_ftrace() {  # escenario archivo
	[ -n "$TRACEFS" ] || return 0
	local t=$TRACEFS
	echo 0 > "$t/tracing_on"
	echo nop > "$t/current_tracer"
	echo 8192 > "$t/buffer_size_kb"
	printf 'security_mmap_file\nsecurity_file_mprotect\n' > "$t/set_graph_function"
	echo 1 > "$t/max_graph_depth"
	echo function_graph > "$t/current_tracer"
	echo > "$t/trace"
	# El hijo escribe su PID en set_ftrace_pid y luego hace exec del benchmark
	bash -c "echo \$\$ > $t/set_ftrace_pid; echo 1 > $t/tracing_on; \
		exec $BENCH mmap $2 20000 > /dev/null; "
	bash -c "echo \$\$ > $t/set_ftrace_pid; \
		exec $BENCH mprotect $2 10000 > /dev/null; "
	echo 0 > "$t/tracing_on"
	cp "$t/trace" "$OUT/ftrace_$1.txt"
	echo > "$t/set_ftrace_pid"
	echo nop > "$t/current_tracer"
	# Promedio de duración por función (en microsegundos)
	for fn in security_mmap_file security_file_mprotect; do
		awk -v fn="$fn" '$0 ~ fn"\\(\\);" {
			for (i = 1; i <= NF; i++) if ($(i+1) == "us") { s += $i; n++; break }
		} END { if (n) printf "%s,%s,%d,%.3f\n", sc, fn, n, s/n }' sc="$1" \
			"$OUT/ftrace_$1.txt" >> "$OUT/ftrace_summary.csv"
	done
}

echo "Benchmark mmap_guard - kernel $(uname -r) - $(nproc) CPUs - $REPS repeticiones"
echo "escenario,funcion,muestras,us_promedio" > "$OUT/ftrace_summary.csv"
setup_ftrace

echo "S0: sin defensa"
run_suite S0_sin_guard "$UNPROT"
run_perf S0_sin_guard "$UNPROT"
run_strace S0_sin_guard "$UNPROT"
run_ftrace S0_sin_guard "$UNPROT"

echo "S1/S2: defensa activa (bloqueo)"
start_guard bench
run_suite S1_guard_no_protegido "$UNPROT"
run_suite S2_guard_protegido "$PROT"
run_perf S2_guard_protegido "$PROT"
run_strace S2_guard_protegido "$PROT"
run_ftrace S1_guard_no_protegido "$UNPROT"
run_ftrace S2_guard_protegido "$PROT"
stop_guard

echo "S3: defensa activa registrando cada acceso (-v)"
start_guard bench_log -v
run_suite S3_guard_protegido_log "$PROT"
stop_guard

# --- Resumen: mediana por escenario y prueba, overhead contra S0 ---------
awk -F, 'NR > 1 { k = $1 "," $3; v[k] = v[k] " " $6; u[$3] = $7 }
END {
	for (k in v) {
		n = split(v[k], a, " ")
		for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (a[j] < a[i]) { t = a[i]; a[i] = a[j]; a[j] = t }
		med[k] = (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
	}
	print "escenario,prueba,unidad,ns_por_op_mediana,overhead_vs_S0_pct"
	split("S0_sin_guard S1_guard_no_protegido S2_guard_protegido S3_guard_protegido_log", S, " ")
	split("mmap mprotect fault read mmapread", T, " ")
	for (s = 1; s <= 4; s++) for (t = 1; t <= 5; t++) {
		k = S[s] "," T[t]; b = med["S0_sin_guard," T[t]]
		if (k in med) printf "%s,%s,%s,%.2f,%.2f\n", S[s], T[t], u[T[t]], med[k], (b ? (med[k] - b) * 100 / b : 0)
	}
}' "$RAW" > "$SUMMARY"

echo
echo "== Resumen (mediana ns por operación) =="
column -t -s, "$SUMMARY" 2>/dev/null || cat "$SUMMARY"
echo
echo "== ftrace (us promedio por llamada al hook) =="
column -t -s, "$OUT/ftrace_summary.csv" 2>/dev/null || cat "$OUT/ftrace_summary.csv"
echo
grep -A5 "Contadores" "$OUT/guard_bench.log"
echo
echo "Resultados en: $OUT"
