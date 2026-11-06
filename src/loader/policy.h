/* SPDX-License-Identifier: GPL-2.0 */
/*
 * policy.h - Lectura del archivo de política (policy.conf) y traducción de
 * rutas a claves (dispositivo, inodo) que entiende el programa eBPF.
 */
#ifndef MMAP_GUARD_POLICY_H
#define MMAP_GUARD_POLICY_H

#include <limits.h>
#include <linux/types.h>
#include "../common.h"

struct policy_entry {
	char               path[PATH_MAX];
	struct file_key    key;
	struct file_policy pol;
};

struct policy_set {
	struct policy_entry *items;
	int                  count;
};

/*
 * Lee el archivo de política. Formato por línea:
 *     <ruta>  <uid_autorizado | ->  <reglas separadas por coma>
 * Reglas: shared-write, private-write, write (= ambas), exec, all.
 * Devuelve 0 si todo salió bien, -1 si hubo error (ya informado por stderr).
 */
int policy_load(const char *conf_path, struct policy_set *set);

void policy_free(struct policy_set *set);

/* Busca la ruta asociada a una clave (para imprimir eventos legibles). */
const char *policy_path_for(const struct policy_set *set, __u32 dev, __u64 ino);

/* Convierte las banderas POL_* a texto ("shared-write,exec"). */
void policy_flags_str(__u32 flags, char *buf, size_t len);

#endif /* MMAP_GUARD_POLICY_H */
