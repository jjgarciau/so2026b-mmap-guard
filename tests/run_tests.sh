#!/usr/bin/env bash
# run_tests.sh - Pruebas de ataque/defensa para mmap_guard.
#
# Fases:
#   1. Línea base: SIN la defensa, se comprueba que todos los ataques funcionan.
#   2. Bloqueo:    CON la defensa, los mismos ataques deben fallar (EPERM) y los
#                  accesos legítimos deben seguir funcionando.
#   3. Integridad: el archivo protegido no cambió tras todos los ataques.
#   4. Auditoría:  en modo -a el acceso se permite pero queda registrado.
#
# Uso: sudo bash tests/run_tests.sh        (o: make test)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GUARD="$ROOT/mmap_guard"
RES="$ROOT/results"
REPORT="$RES/test_report.txt"
AUDIT_LOG="$RES/audit_tests.jsonl"

if [ "$EUID" -ne 0 ]; then
	echo "Ejecutar con sudo (cargar programas eBPF LSM requiere root)." >&2
	exit 1
fi
[ -x "$GUARD" ] && [ -x "$ROOT/tests/mmap_probe" ] || { echo "Compile primero con: make" >&2; exit 1; }

# securityfs no siempre está montado en WSL
[ -r /sys/kernel/security/lsm ] || mount -t securityfs securityfs /sys/kernel/security
if ! tr ',' '\n' < /sys/kernel/security/lsm | grep -qx bpf; then
	echo "BPF LSM no está activo (falta 'bpf' en /sys/kernel/security/lsm)." >&2
	exit 1
fi

mkdir -p "$RES"
: > "$AUDIT_LOG"

# --- Entorno de prueba aislado -------------------------------------------
TESTDIR=$(mktemp -d /tmp/mmap_guard_test.XXXXXX)
chmod 755 "$TESTDIR"
PROBE="$TESTDIR/mmap_probe"              # copia accesible para 'nobody'
install -m 755 "$ROOT/tests/mmap_probe" "$PROBE"

SECRET="$TESTDIR/secreto.dat"
CONFIG="$TESTDIR/config.dat"
SYMLINK="$TESTDIR/enlace_simbolico"
HARDLINK="$TESTDIR/enlace_duro"
POLICY="$TESTDIR/policy.conf"
SECRET_CONTENT="DATO CONFIDENCIAL: no debe modificarse ni ejecutarse desde mmap"

UNPRIV_UID=$(id -u nobody)
UNPRIV_GID=$(id -g nobody)

reset_files() {
	# '>' trunca y reescribe SIN cambiar el inodo (la política sigue aplicando)
	printf '%s\n' "$SECRET_CONTENT" > "$SECRET"
	printf 'modo=produccion\n' > "$CONFIG"
	# 0666: los permisos DAC permiten todo, así que cualquier bloqueo
	# observado proviene del LSM y no de los permisos POSIX.
	chmod 666 "$SECRET" "$CONFIG"
}

reset_files
ln -s "$SECRET" "$SYMLINK"
ln "$SECRET" "$HARDLINK"

cat > "$POLICY" <<EOF
# ruta              uid_autorizado  reglas
$SECRET             -               write,exec
$CONFIG             0               shared-write
EOF

GPID=""
cleanup() {
	[ -n "$GPID" ] && kill -INT "$GPID" 2>/dev/null && wait "$GPID" 2>/dev/null
	rm -rf "$TESTDIR"
}
trap cleanup EXIT

start_guard() {   # $1 = etiqueta, resto = opciones extra
	local tag=$1; shift
	"$GUARD" -c "$POLICY" -l "$AUDIT_LOG" -s "$@" > "$RES/guard_$tag.log" 2>&1 &
	GPID=$!
	for _ in $(seq 1 50); do
		grep -q "activo" "$RES/guard_$tag.log" 2>/dev/null && return 0
		kill -0 "$GPID" 2>/dev/null || break
		sleep 0.2
	done
	echo "mmap_guard no arrancó. Log:" >&2
	cat "$RES/guard_$tag.log" >&2
	GPID=""
	exit 1
}

stop_guard() {
	kill -INT "$GPID" 2>/dev/null
	wait "$GPID" 2>/dev/null
	GPID=""
}

# --- Ejecución de casos ----------------------------------------------------
PASS=0; FAIL=0
{
	echo "Reporte de pruebas mmap_guard - $(date '+%Y-%m-%d %H:%M:%S')"
	echo "Kernel: $(uname -r) | LSM activos: $(cat /sys/kernel/security/lsm)"
	echo "Usuario no privilegiado: nobody (uid=$UNPRIV_UID)"
	echo
	printf '%-10s %-48s %-9s %-9s %s\n' "FASE" "CASO" "ESPERADO" "OBTENIDO" "RESULTADO"
} > "$REPORT"

label() { [ "$1" -eq 0 ] && echo "permite" || echo "deniega"; }

run_case() {  # fase usuario modo archivo esperado descripción
	local phase=$1 user=$2 mode=$3 file=$4 expected=$5 desc=$6 out rc verdict
	if [ "$user" = root ]; then
		out=$("$PROBE" "$mode" "$file" 2>&1); rc=$?
	else
		out=$(setpriv --reuid="$UNPRIV_UID" --regid="$UNPRIV_GID" --clear-groups \
			"$PROBE" "$mode" "$file" 2>&1); rc=$?
	fi
	if [ "$rc" -eq "$expected" ]; then verdict="OK"; PASS=$((PASS+1));
	else verdict="FALLO"; FAIL=$((FAIL+1)); fi
	printf '%-10s %-48s %-9s %-9s %s\n' "$phase" "$desc" "$(label "$expected")" \
		"$(label "$rc")" "$verdict" | tee -a "$REPORT"
	printf '           -> %s\n' "$out" >> "$REPORT"
}

# Casos: usuario | modo | archivo | esperado CON defensa | descripción
CASES=(
	"nobody|read-shared|$SECRET|0|Lectura MAP_SHARED (legitima)"
	"nobody|write-shared|$SECRET|1|Escritura MAP_SHARED"
	"nobody|write-private|$SECRET|1|Escritura MAP_PRIVATE con O_RDONLY (COW)"
	"nobody|exec|$SECRET|1|Mapeo PROT_EXEC (inyeccion de codigo)"
	"nobody|mprotect-write-shared|$SECRET|1|Bypass: mmap(R) + mprotect(W) shared"
	"nobody|mprotect-write-private|$SECRET|1|Bypass: mmap(R) + mprotect(W) private"
	"nobody|mprotect-exec|$SECRET|1|Bypass: mmap(R) + mprotect(X)"
	"nobody|write-shared|$SYMLINK|1|Bypass: enlace simbolico"
	"nobody|write-shared|$HARDLINK|1|Bypass: enlace duro"
	"root|write-shared|$SECRET|1|Root sin autorizacion"
	"nobody|write-shared|$CONFIG|1|Config: escritura shared no autorizada"
	"root|write-shared|$CONFIG|0|Config: escritura shared UID autorizado"
	"nobody|write-private|$CONFIG|0|Config: escritura private (regla no aplica)"
)

echo "== Fase 1: linea base (sin defensa) =="
for c in "${CASES[@]}"; do
	IFS='|' read -r user mode file _ desc <<< "$c"
	reset_files
	run_case "base" "$user" "$mode" "$file" 0 "$desc"
done

echo "== Fase 2: con defensa (modo bloqueo) =="
reset_files
SHA_BEFORE=$(sha256sum "$SECRET" | cut -d' ' -f1)
start_guard bloqueo
for c in "${CASES[@]}"; do
	IFS='|' read -r user mode file expected desc <<< "$c"
	run_case "bloqueo" "$user" "$mode" "$file" "$expected" "$desc"
done
stop_guard

echo "== Fase 3: integridad =="
SHA_AFTER=$(sha256sum "$SECRET" | cut -d' ' -f1)
if [ "$SHA_BEFORE" = "$SHA_AFTER" ]; then r="OK"; PASS=$((PASS+1)); else r="FALLO"; FAIL=$((FAIL+1)); fi
printf '%-10s %-48s %-9s %-9s %s\n' "integridad" "sha256 del secreto antes = despues" \
	"igual" "$([ "$r" = OK ] && echo igual || echo distinto)" "$r" | tee -a "$REPORT"

echo "== Fase 4: modo auditoria =="
reset_files
start_guard auditoria -a
run_case "auditoria" nobody write-shared "$SECRET" 0 "Escritura shared permitida pero registrada"
sleep 0.3
stop_guard
if grep -q "AUDIT(denegar" "$RES/guard_auditoria.log"; then r="OK"; PASS=$((PASS+1)); else r="FALLO"; FAIL=$((FAIL+1)); fi
printf '%-10s %-48s %-9s %-9s %s\n' "auditoria" "Evento registrado en el log" "registra" \
	"$([ "$r" = OK ] && echo registra || echo no)" "$r" | tee -a "$REPORT"

{
	echo
	echo "Total: $PASS OK, $FAIL FALLO"
	echo "Eventos de auditoria: $AUDIT_LOG"
} | tee -a "$REPORT"

[ "$FAIL" -eq 0 ]
