// SPDX-License-Identifier: GPL-2.0
/*
 * policy.c - Parser del archivo de política.
 *
 * La política se expresa con rutas (cómodo para el usuario) pero se aplica
 * por (dispositivo, inodo) en el kernel. Así, un enlace simbólico, un enlace
 * duro o un renombrado del archivo protegido NO eluden la protección.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "policy.h"

/*
 * El kernel codifica dev_t internamente como (major << 20) | minor
 * (MKDEV en include/linux/kdev_t.h), distinto de la codificación de glibc
 * que devuelve stat(). Hay que convertir para que las claves coincidan con
 * inode->i_sb->s_dev.
 */
static __u32 to_kernel_dev(dev_t d)
{
	return ((__u32)major(d) << 20) | (__u32)minor(d);
}

static int parse_rules(const char *s, __u32 *out)
{
	char buf[256];
	char *tok, *save = NULL;
	__u32 flags = 0;

	snprintf(buf, sizeof(buf), "%s", s);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (!strcmp(tok, "shared-write"))
			flags |= POL_DENY_SHARED_WRITE;
		else if (!strcmp(tok, "private-write"))
			flags |= POL_DENY_PRIVATE_WRITE;
		else if (!strcmp(tok, "write"))
			flags |= POL_DENY_SHARED_WRITE | POL_DENY_PRIVATE_WRITE;
		else if (!strcmp(tok, "exec"))
			flags |= POL_DENY_EXEC;
		else if (!strcmp(tok, "all"))
			flags |= POL_DENY_ALL;
		else {
			fprintf(stderr, "regla desconocida: '%s'\n", tok);
			return -1;
		}
	}
	*out = flags;
	return flags ? 0 : -1;
}

static int parse_uid(const char *s, __u32 *uid)
{
	char *end;
	unsigned long v;

	if (!strcmp(s, "-")) {
		*uid = MG_UID_NONE;
		return 0;
	}
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || *end || v >= MG_UID_NONE)
		return -1;
	*uid = (__u32)v;
	return 0;
}

int policy_load(const char *conf_path, struct policy_set *set)
{
	FILE *f;
	char line[PATH_MAX + 512];
	int lineno = 0, cap = 0;

	set->items = NULL;
	set->count = 0;

	f = fopen(conf_path, "r");
	if (!f) {
		fprintf(stderr, "no se pudo abrir %s: %s\n", conf_path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		char path[PATH_MAX], uid_s[32], rules_s[256];
		struct policy_entry *e;
		struct stat st;
		char *p = line;

		lineno++;
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '#' || *p == '\0')
			continue;

		if (sscanf(p, "%4095s %31s %255s", path, uid_s, rules_s) != 3) {
			fprintf(stderr, "%s:%d: se esperaba '<ruta> <uid|-> <reglas>'\n",
				conf_path, lineno);
			goto fail;
		}

		if (set->count == cap) {
			struct policy_entry *n;

			cap = cap ? cap * 2 : 8;
			n = realloc(set->items, (size_t)cap * sizeof(*n));
			if (!n) {
				fprintf(stderr, "sin memoria\n");
				goto fail;
			}
			set->items = n;
		}
		e = &set->items[set->count];
		memset(e, 0, sizeof(*e));

		/* stat() sigue enlaces simbólicos: se protege el archivo real */
		if (stat(path, &st) != 0) {
			fprintf(stderr, "%s:%d: %s: %s\n", conf_path, lineno, path,
				strerror(errno));
			goto fail;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "%s:%d: %s no es un archivo regular\n",
				conf_path, lineno, path);
			goto fail;
		}
		if (parse_uid(uid_s, &e->pol.allowed_uid) != 0) {
			fprintf(stderr, "%s:%d: uid inválido '%s'\n", conf_path, lineno, uid_s);
			goto fail;
		}
		if (parse_rules(rules_s, &e->pol.flags) != 0) {
			fprintf(stderr, "%s:%d: reglas inválidas '%s'\n", conf_path, lineno,
				rules_s);
			goto fail;
		}

		snprintf(e->path, sizeof(e->path), "%s", path);
		e->key.ino = (__u64)st.st_ino;
		e->key.dev = to_kernel_dev(st.st_dev);
		set->count++;
	}

	fclose(f);
	if (set->count == 0) {
		fprintf(stderr, "%s: la política no tiene entradas\n", conf_path);
		return -1;
	}
	return 0;

fail:
	fclose(f);
	policy_free(set);
	return -1;
}

void policy_free(struct policy_set *set)
{
	free(set->items);
	set->items = NULL;
	set->count = 0;
}

const char *policy_path_for(const struct policy_set *set, __u32 dev, __u64 ino)
{
	for (int i = 0; i < set->count; i++)
		if (set->items[i].key.dev == dev && set->items[i].key.ino == ino)
			return set->items[i].path;
	return "?";
}

void policy_flags_str(__u32 flags, char *buf, size_t len)
{
	static const struct { __u32 bit; const char *name; } names[] = {
		{ POL_DENY_SHARED_WRITE,  "shared-write" },
		{ POL_DENY_PRIVATE_WRITE, "private-write" },
		{ POL_DENY_EXEC,          "exec" },
		{ POL_DENY_ALL,           "all" },
	};
	size_t used = 0;

	buf[0] = '\0';
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (!(flags & names[i].bit))
			continue;
		if (used >= len)
			break;
		used += (size_t)snprintf(buf + used, len - used, "%s%s",
					 used ? "," : "", names[i].name);
	}
	if (!buf[0])
		snprintf(buf, len, "-");
}
