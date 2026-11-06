/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - Estructuras compartidas entre el programa eBPF (kernel) y el
 * loader (espacio de usuario).
 *
 * Este archivo NO incluye cabeceras: quien lo incluye debe aportar los tipos
 * __u32/__u64 (vmlinux.h en el lado BPF, <linux/types.h> en el lado usuario).
 */
#ifndef MMAP_GUARD_COMMON_H
#define MMAP_GUARD_COMMON_H

#define MG_COMM_LEN     16
#define MG_MAX_FILES    1024
#define MG_UID_NONE     0xFFFFFFFFu   /* ningún UID autorizado */

/* ---- Banderas de política por archivo (se combinan con OR) ---- */
#define POL_DENY_SHARED_WRITE  (1u << 0) /* MAP_SHARED + PROT_WRITE: modifica el archivo */
#define POL_DENY_PRIVATE_WRITE (1u << 1) /* MAP_PRIVATE + PROT_WRITE: copia COW local     */
#define POL_DENY_EXEC          (1u << 2) /* PROT_EXEC: ejecutar código desde el archivo   */
#define POL_DENY_ALL           (1u << 3) /* cualquier mmap (fuerza la ruta read()/write()) */

/* ---- Identificación del hook que generó el evento ---- */
#define HOOK_MMAP_FILE     1
#define HOOK_FILE_MPROTECT 2

/* ---- Veredicto ---- */
#define VERDICT_ALLOW      0
#define VERDICT_DENY       1
#define VERDICT_AUDIT_DENY 2 /* se habría denegado, pero el modo es solo-auditoría */

/*
 * Clave de la política: (dispositivo, inodo).
 * Se usa el inodo y no la ruta porque la ruta es eludible con enlaces
 * simbólicos, enlaces duros, bind mounts o renombrados; el inodo no.
 * dev usa la codificación interna del kernel: (major << 20) | minor.
 */
struct file_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct file_policy {
	__u32 flags;        /* POL_* */
	__u32 allowed_uid;  /* UID exento de la política, o MG_UID_NONE */
};

/* Configuración global (mapa array de 1 elemento) */
struct guard_config {
	__u32 audit_only;   /* 1 = registrar pero no bloquear */
	__u32 log_allowed;  /* 1 = registrar también los accesos permitidos */
};

/* Evento de auditoría enviado por el ring buffer */
struct mmap_event {
	__u64 ts_ns;
	__u64 ino;
	__u32 dev;
	__u32 pid;
	__u32 uid;
	__u32 hook;      /* HOOK_* */
	__u32 verdict;   /* VERDICT_* */
	__u32 reason;    /* bandera POL_* que disparó la denegación (0 si se permitió) */
	__u64 prot;      /* PROT_* solicitados */
	__u64 flags;     /* MAP_* (mmap) o vm_flags (mprotect) */
	char  comm[MG_COMM_LEN];
};

#endif /* MMAP_GUARD_COMMON_H */
