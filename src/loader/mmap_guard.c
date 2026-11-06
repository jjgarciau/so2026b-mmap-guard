// SPDX-License-Identifier: GPL-2.0
/*
 * mmap_guard.c - Cargador en espacio de usuario.
 *
 * 1. Lee la política (policy.conf) y la traduce a claves (dev, inodo).
 * 2. Carga y verifica el programa eBPF (el verificador del kernel garantiza
 *    que no pueda colgar ni corromper el kernel).
 * 3. Llena los mapas de política/configuración y engancha los hooks LSM.
 * 4. Consume el ring buffer de auditoría e imprime/registra los eventos.
 * 5. Al salir (Ctrl+C o -d), desengancha todo: la protección solo existe
 *    mientras este proceso esté vivo.
 *
 * Uso:  sudo ./mmap_guard -c policy.conf [-a] [-v] [-l audit.jsonl] [-d seg] [-s]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "policy.h"
#include "mmap_guard.skel.h"

#define PROT_READ_  0x1
#define PROT_WRITE_ 0x2
#define PROT_EXEC_  0x4

static volatile sig_atomic_t exiting;

struct options {
	const char *conf;
	const char *log_path;
	int         audit_only;
	int         log_allowed;
	int         duration;
	int         show_stats;
	int         debug;
};

struct run_ctx {
	struct policy_set *set;
	FILE              *log;
	unsigned long long n_events;
};

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Uso: sudo %s -c <policy.conf> [opciones]\n"
		"  -c FILE  archivo de política (obligatorio)\n"
		"  -a       modo solo auditoría (registra, no bloquea)\n"
		"  -v       registrar también los accesos permitidos\n"
		"  -l FILE  guardar eventos en formato JSON Lines\n"
		"  -d SEG   terminar después de SEG segundos (0 = hasta Ctrl+C)\n"
		"  -s       mostrar contadores del kernel al terminar\n"
		"  -D       mensajes de depuración de libbpf\n",
		prog);
}

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static int libbpf_print_debug(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	(void)lvl;
	return vfprintf(stderr, fmt, ap);
}

static void prot_str(__u64 prot, char *buf, size_t len)
{
	snprintf(buf, len, "%s%s%s",
		 (prot & PROT_READ_)  ? "R" : "-",
		 (prot & PROT_WRITE_) ? "W" : "-",
		 (prot & PROT_EXEC_)  ? "X" : "-");
}

static const char *verdict_str(__u32 v)
{
	switch (v) {
	case VERDICT_ALLOW:      return "PERMITIDO";
	case VERDICT_DENY:       return "DENEGADO";
	case VERDICT_AUDIT_DENY: return "AUDIT(denegaría)";
	default:                 return "?";
	}
}

static const char *hook_str(__u32 h)
{
	return h == HOOK_MMAP_FILE ? "mmap" : h == HOOK_FILE_MPROTECT ? "mprotect" : "?";
}

/* Callback del ring buffer: un evento por llamada */
static int handle_event(void *ctx, void *data, size_t size)
{
	struct run_ctx *rc = ctx;
	const struct mmap_event *e = data;
	char prot[8], reason[64], when[32];
	const char *path;
	struct timespec now;
	struct tm tm;

	if (size < sizeof(*e))
		return 0;

	rc->n_events++;
	path = policy_path_for(rc->set, e->dev, e->ino);
	prot_str(e->prot, prot, sizeof(prot));
	policy_flags_str(e->reason, reason, sizeof(reason));

	clock_gettime(CLOCK_REALTIME, &now);
	localtime_r(&now.tv_sec, &tm);
	strftime(when, sizeof(when), "%H:%M:%S", &tm);

	printf("%s %-17s %-8s pid=%-6u uid=%-5u comm=%-15.16s prot=%s %s=0x%llx regla=%s archivo=%s\n",
	       when, verdict_str(e->verdict), hook_str(e->hook), e->pid, e->uid,
	       e->comm, prot, e->hook == HOOK_MMAP_FILE ? "flags" : "vm_flags",
	       (unsigned long long)e->flags, reason, path);
	fflush(stdout);

	if (rc->log) {
		fprintf(rc->log,
			"{\"ts_ns\":%llu,\"verdict\":\"%s\",\"hook\":\"%s\",\"pid\":%u,"
			"\"uid\":%u,\"comm\":\"%.16s\",\"prot\":\"%s\",\"flags\":%llu,"
			"\"reason\":\"%s\",\"dev\":%u,\"ino\":%llu,\"path\":\"%s\"}\n",
			(unsigned long long)e->ts_ns, verdict_str(e->verdict),
			hook_str(e->hook), e->pid, e->uid, e->comm, prot,
			(unsigned long long)e->flags, reason, e->dev,
			(unsigned long long)e->ino, path);
		fflush(rc->log);
	}
	return 0;
}

static void print_stats(struct mmap_guard_bpf *skel)
{
	static const char *names[] = {
		"hooks evaluados", "sobre archivos protegidos", "denegados",
		"denegarían (auditoría)",
	};
	int ncpu = libbpf_num_possible_cpus();
	int fd = bpf_map__fd(skel->maps.stats_map);
	__u64 *vals;

	if (ncpu <= 0)
		return;
	vals = calloc((size_t)ncpu, sizeof(*vals));
	if (!vals)
		return;

	printf("\n--- Contadores del kernel ---\n");
	for (__u32 k = 0; k < sizeof(names) / sizeof(names[0]); k++) {
		__u64 total = 0;

		if (bpf_map_lookup_elem(fd, &k, vals) == 0)
			for (int c = 0; c < ncpu; c++)
				total += vals[c];
		printf("  %-28s %llu\n", names[k], (unsigned long long)total);
	}
	free(vals);
}

static int parse_args(int argc, char **argv, struct options *o)
{
	int c;

	memset(o, 0, sizeof(*o));
	while ((c = getopt(argc, argv, "c:avl:d:sDh")) != -1) {
		switch (c) {
		case 'c': o->conf = optarg; break;
		case 'a': o->audit_only = 1; break;
		case 'v': o->log_allowed = 1; break;
		case 'l': o->log_path = optarg; break;
		case 'd': o->duration = atoi(optarg); break;
		case 's': o->show_stats = 1; break;
		case 'D': o->debug = 1; break;
		default:  return -1;
		}
	}
	return o->conf ? 0 : -1;
}

int main(int argc, char **argv)
{
	struct options opt;
	struct policy_set set = { 0 };
	struct run_ctx rc = { 0 };
	struct mmap_guard_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct guard_config cfg = { 0 };
	__u32 zero = 0;
	time_t deadline = 0;
	int err = 1;

	if (parse_args(argc, argv, &opt) != 0) {
		usage(argv[0]);
		return 2;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "se requieren privilegios de root (CAP_BPF + CAP_MAC_ADMIN)\n");
		return 1;
	}

	libbpf_set_print(opt.debug ? libbpf_print_debug : libbpf_print);

	if (policy_load(opt.conf, &set) != 0)
		return 1;
	rc.set = &set;

	if (opt.log_path) {
		rc.log = fopen(opt.log_path, "a");
		if (!rc.log) {
			fprintf(stderr, "no se pudo abrir %s: %s\n", opt.log_path, strerror(errno));
			goto out;
		}
	}

	/* Abrir + cargar: aquí actúa el verificador eBPF del kernel */
	skel = mmap_guard_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "error cargando el programa eBPF: %s\n"
			"¿Está 'bpf' en /sys/kernel/security/lsm?\n", strerror(errno));
		goto out;
	}

	/* Configuración global */
	cfg.audit_only  = (__u32)opt.audit_only;
	cfg.log_allowed = (__u32)opt.log_allowed;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.config_map), &zero, &cfg, BPF_ANY)) {
		fprintf(stderr, "error escribiendo config_map: %s\n", strerror(errno));
		goto out;
	}

	/* Política: una entrada por archivo protegido */
	for (int i = 0; i < set.count; i++) {
		struct policy_entry *e = &set.items[i];
		char rules[64];

		if (bpf_map_update_elem(bpf_map__fd(skel->maps.policy_map), &e->key,
					&e->pol, BPF_ANY)) {
			fprintf(stderr, "error escribiendo policy_map: %s\n", strerror(errno));
			goto out;
		}
		policy_flags_str(e->pol.flags, rules, sizeof(rules));
		printf("[politica] %s (dev=%u ino=%llu) reglas=%s ", e->path,
		       e->key.dev, (unsigned long long)e->key.ino, rules);
		if (e->pol.allowed_uid == MG_UID_NONE)
			printf("uid_autorizado=ninguno\n");
		else
			printf("uid_autorizado=%u\n", e->pol.allowed_uid);
	}

	/* Enganchar los hooks LSM: desde aquí la política está activa */
	if (mmap_guard_bpf__attach(skel)) {
		fprintf(stderr, "error enganchando los hooks LSM: %s\n", strerror(errno));
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &rc, NULL);
	if (!rb) {
		fprintf(stderr, "error creando el ring buffer\n");
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	if (opt.duration > 0)
		deadline = time(NULL) + opt.duration;

	printf("[mmap_guard] activo (modo %s). Ctrl+C para salir.\n",
	       opt.audit_only ? "AUDITORIA" : "BLOQUEO");
	fflush(stdout);

	while (!exiting) {
		int n = ring_buffer__poll(rb, 100 /* ms */);

		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "error leyendo el ring buffer: %d\n", n);
			goto out;
		}
		if (deadline && time(NULL) >= deadline)
			break;
	}
	/* Vaciar eventos pendientes antes de salir */
	ring_buffer__consume(rb);

	if (opt.show_stats)
		print_stats(skel);
	printf("[mmap_guard] detenido. Eventos recibidos: %llu\n", rc.n_events);
	err = 0;

out:
	ring_buffer__free(rb);
	mmap_guard_bpf__destroy(skel); /* desengancha hooks y libera mapas */
	if (rc.log)
		fclose(rc.log);
	policy_free(&set);
	return err;
}
