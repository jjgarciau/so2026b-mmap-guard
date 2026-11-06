# Entrega 3 – SO2026B: Seguridad de archivos mapeados con `mmap()` en la capa de kernel

Parcial práctico-teórico (25%) – Sistemas Operativos, Universidad EAFIT, 2026-2.
Integrantes: Juan José García y Juan Esteban Jiménez.
Referencia base: [SO2026B / USOS / CapaKernel](https://github.com/evalenciEAFIT/SO2026B/tree/main/USOS/CapaKernel)

## Objetivo
Reforzar la seguridad, integridad y control de acceso sobre archivos proyectados con `mmap()`
desde el kernel: bloquear mapeos de escritura o ejecución no autorizados sobre archivos
protegidos, impedir la escalada de permisos vía `mprotect()` y auditar los accesos.

## Arquitectura

```
 Espacio de usuario (Ring 3)                       Kernel (Ring 0)
 ┌──────────────────────────┐   mmap()/mprotect()  ┌──────────────────────────────────────┐
 │ proceso (atacante/legít.)│ ───────────────────▶ │ vm_mmap_pgoff / do_mprotect_pkey     │
 └──────────────────────────┘                      │   └─ security_mmap_file()            │
                                                   │   └─ security_file_mprotect()        │
 ┌──────────────────────────┐   policy_map         │        └─ eBPF LSM: mmap_guard.bpf.c │
 │ mmap_guard (loader C)    │ ───────────────────▶ │           · lookup (dev, inodo)      │
 │  · lee policy.conf       │   config_map         │           · reglas + UID efectivo    │
 │  · carga/engancha eBPF   │ ◀─────────────────── │           · 0 o -EPERM               │
 │  · imprime auditoría     │   ring buffer events │                                      │
 └──────────────────────────┘                      └──────────────────────────────────────┘
```

- **eBPF LSM** (`lsm/mmap_file`, `lsm/file_mprotect`): se decide en el alta/modificación de la
  VMA, antes de que existan PTEs. Después del primer page fault la MMU atiende los accesos sin
  entrar al kernel, por eso el control se hace sobre los bits de la VMA.
- **Política por (dispositivo, inodo)**, no por ruta: enlaces simbólicos, enlaces duros y
  renombrados no la eluden.
- **Loader en C (libbpf + skeleton)**: carga la política, activa los hooks y muestra la auditoría.
  La protección dura mientras el loader esté corriendo.

## Estructura
| Ruta | Contenido |
|---|---|
| `src/common.h` | Estructuras compartidas kernel/usuario (política, eventos) |
| `src/bpf/mmap_guard.bpf.c` | Programa eBPF LSM |
| `src/loader/` | Loader (`mmap_guard.c`) y parser de política (`policy.c`) |
| `tests/mmap_probe.c` | Programa que intenta cada tipo de acceso mmap/mprotect |
| `tests/run_tests.sh` | Pruebas: línea base, bloqueo, integridad y auditoría |
| `tests/race_cow.c`, `tests/run_race.sh` | Carrera madvise vs. escrituras privadas (patrón Dirty COW) |
| `bench/` | Benchmark de overhead (`bench_mmap.c`, `run_bench.sh`: perf, strace, ftrace) |
| `results/` | Reportes y logs de pruebas |
| `docs/` | Informe, diagramas y configuración del entorno (`docs/entorno/.wslconfig`) |
| `bitacora_ia/` | Registro de prompts y alucinaciones (Parte II) |

## Requisitos del entorno
- WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`, Ubuntu 24.04
- `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` y `bpf` en el parámetro `lsm=`
  (ver `docs/entorno/.wslconfig`). Verificar con `cat /sys/kernel/security/lsm`.
- Paquetes: `clang llvm libbpf-dev libelf-dev zlib1g-dev build-essential linux-tools-generic`

## Compilación
```bash
make            # genera build/vmlinux.h, build/mmap_guard.bpf.o, el skeleton,
                # el binario ./mmap_guard y tests/mmap_probe (con -Werror)
make clean
```

## Uso
```bash
cp policy.example.conf policy.conf    # ajustar rutas y UIDs
sudo ./mmap_guard -c policy.conf -s   # Ctrl+C para detener
```
Opciones: `-a` solo auditoría, `-v` registrar también accesos permitidos,
`-l archivo.jsonl` guardar eventos, `-d SEG` duración, `-s` contadores al salir.

Ejemplo de prueba manual (en otra terminal):
```bash
./tests/mmap_probe write-shared /ruta/al/secreto.dat   # -> DENEGADO mmap: Operation not permitted
```

## Pruebas
```bash
make test       # = sudo bash tests/run_tests.sh   (ataque/defensa)
make race       # = sudo bash tests/run_race.sh    (condición de carrera)
make bench      # = sudo bash bench/run_bench.sh   (overhead)
```
Ejecuta los mismos ataques sin y con la defensa, verifica la integridad del archivo y el modo
auditoría. Reporte en `results/test_report.txt`.

## Estado
- [x] Entorno (BPF LSM activo, clang, libbpf, bpftool)
- [x] Parte I – 10 preguntas (informe)
- [x] Parte II – Estrategia con IA (informe)
- [x] Parte III – Programa eBPF, loader, Makefile y pruebas (29/29 OK en WSL, 2026-11-06)
- [x] Parte III – Prueba de carrera y benchmark (scripts)
- [x] Carrera 4/4 OK y benchmark ejecutados en WSL (`results/`)
- [x] Informe final: `docs/Informe_Parcial25_SO_mmap_guard.docx` / `.pdf`
