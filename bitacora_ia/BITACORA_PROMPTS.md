# Bitácora de uso de IA (insumo para la Parte II)

Registro real de las interacciones con IA durante la entrega. Cada fila debe reflejar lo que
efectivamente se pidió y obtuvo; la sección de alucinaciones solo incluye errores verificados.

Herramienta: Claude (Cowork).

## Prompts

| # | Fecha | Fase | Contexto | Rol asignado | Restricción | Resultado esperado | Resultado obtenido / verificación |
|---|---|---|---|---|---|---|---|
| 1 | 2026-11-05 | Exploración | Enunciado del parcial (PDF) | Asistente de planeación técnica | Distinguir qué depende de la estudiante | Plan de desarrollo y lista de dependencias | Plan por fases; propuso eBPF LSM vs. LKM con kprobe/ftrace. Pendiente verificar las afirmaciones técnicas contra el código del kernel. |
| 2 | 2026-11-05 | Exploración / entorno | Repo del curso + Linux en WSL | Asistente de entorno | Kernel de WSL2, sin VM aparte | Viabilidad de WSL para LKM/eBPF | Entregó un diagnóstico (`/proc/config.gz`, BTF, securityfs). Ver hallazgo H1. |
| 3 | 2026-11-05 | Entorno | BPF LSM compilado pero inactivo en WSL2 | Asistente de entorno | No recompilar el kernel | Activar `bpf` en `lsm=` | `.wslconfig` con `kernelCommandLine`; verificado: `/sys/kernel/security/lsm` termina en `bpf`. |
| 4 | 2026-11-06 | Generación de código | Entorno listo (Ubuntu 24.04, kernel 6.6 WSL2, libbpf 1.3, clang 18) | Desarrollador de sistemas en C/eBPF | Hooks LSM reales, clean build, política por inodo, cubrir bypass por `mprotect` | Programa eBPF + loader + Makefile + pruebas | Código generado; clean build y `make test` en WSL: 29/29 OK (ver `results/test_report.txt`). Ajustes previos: H2–H4. |
| 5 | 2026-11-06 | Pruebas y documentación | Implementación validada (29/29); entrega en pareja el mismo día | Ingeniero de pruebas y redactor técnico | Pruebas de carrera y overhead reproducibles (perf/strace/ftrace); respuestas citando estructuras del kernel 6.6 | `tests/race_cow.c`, `tests/run_race.sh`, `bench/`, informe Word |
| 6 | 2026-11-06 | Auditoría | Informe completo + rúbrica | Auditor técnico frente a la rúbrica | Verificar cada símbolo/versión contra el árbol 6.6 | Detectó y corrigió H7–H10; tabla de prompts con texto literal |

## Alucinaciones, supuestos erróneos y correcciones

| ID | Qué sugirió la IA | Cómo se detectó | Verificación / fuente | Corrección aplicada |
|---|---|---|---|---|
| H1 | Supuso que el kernel de WSL2 podría no traer soporte BPF LSM | Diagnóstico en la máquina real | `CONFIG_BPF_LSM=y` sí está; lo que falta es `bpf` en `CONFIG_LSM` (no está activo en el arranque) | Activar `bpf` vía `kernelCommandLine` en `.wslconfig` |
| H2 | Flags de compilación BPF con `-Wall -Wextra -Werror` sin excepciones | Error de compilación: la macro `BPF_PROG` genera un parámetro `ctx` sin usar | `bpf_tracing.h` (libbpf 1.3), línea de la macro `BPF_PROG` | Se mantiene `-Werror` pero con `-Wno-unused-parameter` solo para el objeto BPF (documentado en el Makefile) |
| H3 | Primera versión leía campos del kernel con `BPF_CORE_READ()` | Revisión: ese macro usa el helper `bpf_probe_read_kernel()`, que el kernel deshabilita con `lockdown=confidentiality` | `kernel/trace/bpf_trace.c` (`security_locked_down(LOCKDOWN_BPF_READ_KERNEL)`) | Se cambió a accesos directos a punteros BTF (`file->f_inode->i_ino`, `bpf_get_current_task_btf()`) |
| H4 | Se intentó validar la carga en el entorno de la IA (kernel 6.18 con BPF LSM activo) | La carga de CUALQUIER programa LSM (incluso uno trivial) devolvió EPERM | Entorno de la IA restringido; no prueba nada sobre el código | La validación en ejecución se hace solo en WSL (evidencia real en `results/`) |
| H5 | Ejemplo de bpftrace con índices de argumentos del hook LSM (reqprot, prot, flags) aplicados a `security_mmap_file` | Revisión del borrador de la pregunta 7 | `security_mmap_file(file, prot, flags)` tiene 3 argumentos (`security/security.c`) | Índices corregidos: `arg1`=prot, `arg2`=flags |
| H6 | Medición con ftrace (`function_graph` + `set_graph_function` + filtro por PID) en `run_bench.sh` | En WSL2 el trace salió vacío (solo cabecera) | Causa no diagnosticada antes de la entrega; perf y strace sí funcionaron | Costo del hook medido por diferencia de tiempos S1/S2 vs S0; ftrace queda como pendiente |
| H7 | Respuesta 1 citaba `folio_add_file_rmap_ptes()` | Auditoría de símbolos por versión | Función introducida en 6.8; en 6.6 `set_pte_range()` usa `folio_add_file_rmap_range()` | Nombre corregido para 6.6 |
| H8 | Respuesta 1: el fallo de página siempre usa el lock por VMA desde 6.4 | Auditoría contra `mm/memory.c` 6.6 | En 6.4–6.6 varios fallos de archivo devuelven `VM_FAULT_RETRY` y usan `mmap_lock` | Afirmación matizada |
| H9 | Respuesta 5: lectura descifra con `fscrypt_decrypt_pagecache_blocks()` | Auditoría contra `fs/ext4/readpage.c` | Readahead usa `fscrypt_decrypt_bio()` | Corregido y precisado |
| H10 | Respuesta 4: despacho por `switch` "desde 6.9" | Auditoría de versión | Parche BHI (CVE-2024-2201) retroportado a estables (6.6.26+) | Precisado: aplica también a 6.6.87 |
## Procedimiento de validación
1. Compilar contra el BTF del kernel en ejecución (`/sys/kernel/btf/vmlinux` → `vmlinux.h`).
2. Compilación limpia (`-Wall -Wextra -Werror`).
3. Comprobar símbolos/hooks en el árbol del kernel 6.6 (`include/linux/lsm_hook_defs.h`).
4. Prueba en WSL con snapshot/recuperación (`wsl --shutdown`).
