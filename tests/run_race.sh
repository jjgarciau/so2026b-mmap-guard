#!/usr/bin/env bash
# run_race.sh - Pruebas de condición de carrera madvise(MADV_DONTNEED) vs
# escrituras sobre páginas privadas (patrón Dirty COW), sin y con mmap_guard.
#
# Escenarios (usuario 'nobody' contra un archivo de root con permisos 0444):
#   1. Sin defensa, /proc/self/mem  -> el kernel debe mantener el archivo intacto
#   2. Sin defensa, puntero directo -> COW: el archivo debe quedar intacto
#   3. Con defensa, puntero directo -> mmap(PROT_WRITE, MAP_PRIVATE) denegado
#   4. Con defensa, /proc/self/mem  -> mmap(PROT_READ) permitido; la integridad
#      la garantiza el kernel (límite del LSM: no ve escrituras FOLL_FORCE)
#
# Uso: sudo bash tests/run_race.sh [segundos_por_escenario]   (por defecto 10)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GUARD="$ROOT/mmap_guard"
RES="$ROOT/results"
REPORT="$RES/race_report.txt"
SECS=${1:-10}

[ "$EUID" -eq 0 ] || { echo "Ejecutar con sudo." >&2; exit 1; }
[ -x "$GUARD" ] || { echo "Compile primero con: make" >&2; exit 1; }
[ -r /sys/kernel/security/lsm ] || mount -t securityfs securityfs /sys/kernel/security
mkdir -p "$RES"

# Compilar el programa de carrera si hace falta (mismas banderas estrictas)
if [ ! -x "$ROOT/tests/race_cow" ] || [ "$ROOT/tests/race_cow.c" -nt "$ROOT/tests/race_cow" ]; then
	gcc -O2 -g -std=gnu11 -Wall -Wextra -Werror -pthread \
		-o "$ROOT/tests/race_cow" "$ROOT/tests/race_cow.c" || exit 1
fi

TESTDIR=$(mktemp -d /tmp/mmap_guard_race.XXXXXX)
chmod 755 "$TESTDIR"
RACE="$TESTDIR/race_cow"
install -m 755 "$ROOT/tests/race_cow" "$RACE"
TARGET="$TESTDIR/solo_lectura.dat"
POLICY="$TESTDIR/policy.conf"

# Archivo de root, solo lectura para todos (como /etc/passwd en Dirty COW)
head -c 8192 /dev/zero | tr '\0' 'A' > "$TARGET"
chown root:root "$TARGET"
chmod 444 "$TARGET"
SHA_ORIG=$(sha256sum "$TARGET" | cut -d' ' -f1)

echo "$TARGET - write,exec" > "$POLICY"

GPID=""
cleanup() {
	[ -n "$GPID" ] && kill -INT "$GPID" 2>/dev/null && wait "$GPID" 2>/dev/null
	rm -rf "$TESTDIR"
}
trap cleanup EXIT

start_guard() {
	"$GUARD" -c "$POLICY" -s > "$RES/guard_race.log" 2>&1 &
	GPID=$!
	for _ in $(seq 1 50); do
		grep -q "activo" "$RES/guard_race.log" 2>/dev/null && return 0
		kill -0 "$GPID" 2>/dev/null || break
		sleep 0.2
	done
	cat "$RES/guard_race.log" >&2
	exit 1
}
stop_guard() { kill -INT "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null; GPID=""; }

PASS=0; FAIL=0
{
	echo "Reporte de carrera mmap_guard - $(date '+%Y-%m-%d %H:%M:%S')"
	echo "Kernel: $(uname -r) | CPUs: $(nproc) | segundos por escenario: $SECS"
	echo "Archivo objetivo: root:root 0444, 8 KiB | atacante: nobody"
	echo
} > "$REPORT"

run_scenario() {  # descripcion modo codigo_esperado
	local desc=$1 mode=$2 expected=$3 out rc sha verdict
	out=$(setpriv --reuid="$(id -u nobody)" --regid="$(id -g nobody)" --clear-groups \
		"$RACE" "$TARGET" "$mode" "$SECS" 2>&1); rc=$?
	sha=$(sha256sum "$TARGET" | cut -d' ' -f1)
	if [ "$rc" -eq "$expected" ] && [ "$sha" = "$SHA_ORIG" ]; then
		verdict="OK"; PASS=$((PASS+1))
	else
		verdict="FALLO"; FAIL=$((FAIL+1))
	fi
	{
		echo "[$verdict] $desc"
		echo "        $out"
		echo "        sha256 igual al original: $([ "$sha" = "$SHA_ORIG" ] && echo si || echo NO)"
	} | tee -a "$REPORT"
}

echo "== Sin defensa ==" | tee -a "$REPORT"
run_scenario "1. madvise vs /proc/self/mem (Dirty COW) sin defensa" procmem 0
run_scenario "2. madvise vs escritura directa COW sin defensa"      direct  0

echo "== Con defensa (mmap_guard, regla write,exec) ==" | tee -a "$REPORT"
start_guard
run_scenario "3. madvise vs escritura directa COW con defensa"      direct  1
run_scenario "4. madvise vs /proc/self/mem con defensa"             procmem 0
stop_guard
grep -E "DENEGADO|Contadores|denegados" "$RES/guard_race.log" | head -5 >> "$REPORT"

echo | tee -a "$REPORT"
echo "Total: $PASS OK, $FAIL FALLO" | tee -a "$REPORT"
[ "$FAIL" -eq 0 ]
