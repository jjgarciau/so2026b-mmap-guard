// SPDX-License-Identifier: GPL-2.0
/*
 * mmap_guard.bpf.c - Programa eBPF LSM que refuerza la seguridad de archivos
 * proyectados con mmap().
 *
 * Se engancha a dos puntos del framework LSM (Linux Security Modules):
 *
 *   lsm/mmap_file      -> security_mmap_file(): se invoca desde vm_mmap_pgoff()
 *                         ANTES de do_mmap(), es decir, antes de crear la VMA.
 *                         Es el punto donde se decide si el mapeo existe o no.
 *
 *   lsm/file_mprotect  -> security_file_mprotect(): se invoca desde
 *                         do_mprotect_pkey() antes de cambiar los permisos de
 *                         una VMA existente. Sin este hook, un atacante podría
 *                         mapear con PROT_READ (permitido) y luego "subir" a
 *                         PROT_WRITE o PROT_EXEC con mprotect().
 *
 * Por qué aquí y no en el page fault: una vez la PTE está presente, la MMU
 * atiende los accesos sin entrar al kernel. El único momento en que el kernel
 * controla los permisos de TODA la región es al crear o modificar la VMA; los
 * bits de la VMA (VM_WRITE, VM_EXEC, VM_SHARED) son los que luego se copian a
 * las PTE en cada fallo de página.
 *
 * Nota: el hook se llama "mmap_file" desde Linux 3.5; el nombre antiguo
 * "file_mmap" (que aparece en documentación vieja) ya no existe.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"

char LICENSE[] SEC("license") = "GPL"; /* obligatorio para programas LSM */

/* vmlinux.h no trae macros (#define), así que se declaran aquí */
#define EPERM               1
#define PROT_WRITE          0x2
#define PROT_EXEC           0x4
#define MAP_SHARED          0x01
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE            0x0f
#define VM_SHARED           0x00000008UL

/* ------------------------------------------------------------------ */
/* Mapas                                                               */
/* ------------------------------------------------------------------ */

/* Política: (dev, inodo) -> banderas + UID autorizado. La llena el loader. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MG_MAX_FILES);
	__type(key, struct file_key);
	__type(value, struct file_policy);
} policy_map SEC(".maps");

/* Configuración global (modo auditoría, etc.) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_config);
} config_map SEC(".maps");

/* Contadores por CPU (sin contención entre núcleos) para medir actividad */
enum { STAT_CHECKS = 0, STAT_PROTECTED, STAT_DENIED, STAT_AUDIT_DENIED, STAT_MAX };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* Canal de auditoría hacia espacio de usuario */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats_map, &idx);

	if (v)
		*v += 1;
}

static __always_inline struct guard_config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&config_map, &zero);
}

/*
 * UID efectivo del proceso actual (el que cuenta para permisos).
 *
 * Se usan accesos directos a punteros BTF (task->cred->euid) en lugar de
 * BPF_CORE_READ(): este último usa el helper bpf_probe_read_kernel(), que el
 * kernel bloquea cuando está en modo lockdown=confidentiality. Los accesos
 * directos siguen siendo CO-RE (vmlinux.h marca todo con
 * preserve_access_index) y el verificador los valida por tipo.
 */
static __always_inline __u32 current_euid(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return task->cred->euid.val;
}

/*
 * Busca la política del archivo a partir de su inodo.
 * Devuelve NULL si el archivo no está protegido (caso común: costo = 1 lookup).
 */
static __always_inline struct file_policy *
lookup_policy(struct file *file, struct file_key *key)
{
	struct inode *inode = file->f_inode;

	if (!inode)
		return NULL;
	key->ino = inode->i_ino;
	key->dev = inode->i_sb->s_dev;
	key->pad = 0;
	return bpf_map_lookup_elem(&policy_map, key);
}

/*
 * Decide qué regla (si alguna) viola la solicitud.
 * Devuelve la bandera POL_* violada, o 0 si se permite.
 */
static __always_inline __u32 violated_rule(__u32 pol, int shared,
					   unsigned long prot, int is_mmap)
{
	if (is_mmap && (pol & POL_DENY_ALL))
		return POL_DENY_ALL;
	if ((prot & PROT_WRITE) && shared && (pol & POL_DENY_SHARED_WRITE))
		return POL_DENY_SHARED_WRITE;
	if ((prot & PROT_WRITE) && !shared && (pol & POL_DENY_PRIVATE_WRITE))
		return POL_DENY_PRIVATE_WRITE;
	if ((prot & PROT_EXEC) && (pol & POL_DENY_EXEC))
		return POL_DENY_EXEC;
	return 0;
}

static __always_inline void emit_event(struct file_key *key, __u32 uid,
				       __u32 hook, __u32 verdict, __u32 reason,
				       unsigned long prot, unsigned long flags)
{
	struct mmap_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; /* buffer lleno: se pierde el evento, nunca se bloquea */
	e->ts_ns   = bpf_ktime_get_ns();
	e->ino     = key->ino;
	e->dev     = key->dev;
	e->pid     = bpf_get_current_pid_tgid() >> 32;
	e->uid     = uid;
	e->hook    = hook;
	e->verdict = verdict;
	e->reason  = reason;
	e->prot    = prot;
	e->flags   = flags;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/*
 * Lógica común a ambos hooks. Devuelve 0 (permitir) o -EPERM (denegar).
 */
static __always_inline int enforce(struct file *file, unsigned long prot,
				   unsigned long flags, int shared, __u32 hook)
{
	struct file_key key = {};
	struct file_policy *pol;
	struct guard_config *cfg;
	__u32 uid, reason, verdict;

	stat_inc(STAT_CHECKS);

	pol = lookup_policy(file, &key);
	if (!pol)
		return 0;               /* archivo no protegido */
	stat_inc(STAT_PROTECTED);

	cfg = get_config();
	uid = current_euid();
	reason = violated_rule(pol->flags, shared, prot, hook == HOOK_MMAP_FILE);

	/* El UID autorizado queda exento de la política */
	if (reason && uid == pol->allowed_uid)
		reason = 0;

	if (!reason) {
		if (cfg && cfg->log_allowed)
			emit_event(&key, uid, hook, VERDICT_ALLOW, 0, prot, flags);
		return 0;
	}

	if (cfg && cfg->audit_only) {
		verdict = VERDICT_AUDIT_DENY;
		stat_inc(STAT_AUDIT_DENIED);
	} else {
		verdict = VERDICT_DENY;
		stat_inc(STAT_DENIED);
	}
	emit_event(&key, uid, hook, verdict, reason, prot, flags);

	return verdict == VERDICT_DENY ? -EPERM : 0;
}

/* ------------------------------------------------------------------ */
/* Hooks LSM                                                           */
/* ------------------------------------------------------------------ */

/*
 * int security_mmap_file(struct file *file, unsigned long prot,
 *                        unsigned long flags)
 * El hook recibe además reqprot (lo que pidió el usuario) y prot (lo que el
 * kernel aplicará, p. ej. con READ_IMPLIES_EXEC). En BPF LSM se agrega un
 * último argumento "ret" con el resultado de los LSM anteriores en la pila.
 */
SEC("lsm/mmap_file")
int BPF_PROG(guard_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags, int ret)
{
	int shared;

	if (ret != 0)
		return ret;     /* otro LSM ya denegó: respetar su decisión */
	if (!file)
		return 0;       /* mapeo anónimo: no hay archivo que proteger */

	shared = (flags & MAP_TYPE) == MAP_SHARED ||
		 (flags & MAP_TYPE) == MAP_SHARED_VALIDATE;

	return enforce(file, prot, flags, shared, HOOK_MMAP_FILE);
}

/*
 * int security_file_mprotect(struct vm_area_struct *vma,
 *                            unsigned long reqprot, unsigned long prot)
 * Cierra el bypass "mapear como lectura y luego mprotect(PROT_WRITE|PROT_EXEC)".
 */
SEC("lsm/file_mprotect")
int BPF_PROG(guard_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	struct file *file;
	unsigned long vm_flags;

	if (ret != 0)
		return ret;

	file = vma->vm_file;
	if (!file)
		return 0;

	vm_flags = vma->vm_flags;

	return enforce(file, prot, vm_flags, (vm_flags & VM_SHARED) != 0,
		       HOOK_FILE_MPROTECT);
}
