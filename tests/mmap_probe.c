// SPDX-License-Identifier: GPL-2.0
/*
 * mmap_probe.c - Programa de prueba que intenta un tipo concreto de acceso
 * mmap()/mprotect() sobre un archivo e informa si el kernel lo permitió.
 *
 * Uso: mmap_probe <modo> <archivo>
 *
 * Modos:
 *   read-shared             O_RDONLY + PROT_READ + MAP_SHARED
 *   write-shared            O_RDWR   + PROT_READ|PROT_WRITE + MAP_SHARED  (modifica el archivo)
 *   write-private           O_RDONLY + PROT_READ|PROT_WRITE + MAP_PRIVATE (COW: el archivo no cambia)
 *   exec                    O_RDONLY + PROT_READ|PROT_EXEC  + MAP_PRIVATE
 *   mprotect-write-shared   mapea R + MAP_SHARED  y luego mprotect(R|W)
 *   mprotect-write-private  mapea R + MAP_PRIVATE y luego mprotect(R|W)
 *   mprotect-exec           mapea R + MAP_PRIVATE y luego mprotect(R|X)
 *
 * Código de salida: 0 = permitido, 1 = denegado (EPERM/EACCES), 2 = otro error.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXIT_ALLOWED 0
#define EXIT_DENIED  1
#define EXIT_ERROR   2

struct mode {
	const char *name;
	int open_flags;
	int prot;          /* protección inicial de mmap() */
	int map_flags;
	int mprotect_to;   /* 0 = no llamar mprotect() */
	int write_byte;    /* 1 = escribir a través del puntero */
};

static const struct mode modes[] = {
	{ "read-shared",            O_RDONLY, PROT_READ,              MAP_SHARED,  0, 0 },
	{ "write-shared",           O_RDWR,   PROT_READ | PROT_WRITE, MAP_SHARED,  0, 1 },
	{ "write-private",          O_RDONLY, PROT_READ | PROT_WRITE, MAP_PRIVATE, 0, 1 },
	{ "exec",                   O_RDONLY, PROT_READ | PROT_EXEC,  MAP_PRIVATE, 0, 0 },
	{ "mprotect-write-shared",  O_RDWR,   PROT_READ, MAP_SHARED,  PROT_READ | PROT_WRITE, 1 },
	{ "mprotect-write-private", O_RDONLY, PROT_READ, MAP_PRIVATE, PROT_READ | PROT_WRITE, 1 },
	{ "mprotect-exec",          O_RDONLY, PROT_READ, MAP_PRIVATE, PROT_READ | PROT_EXEC,  0 },
};

static int report_denied(const char *what, int err)
{
	printf("DENEGADO  %s: %s\n", what, strerror(err));
	return (err == EPERM || err == EACCES) ? EXIT_DENIED : EXIT_ERROR;
}

int main(int argc, char **argv)
{
	const struct mode *m = NULL;
	struct stat st;
	char *p, before, on_disk;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "uso: %s <modo> <archivo>\n", argv[0]);
		return EXIT_ERROR;
	}
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
		if (!strcmp(argv[1], modes[i].name))
			m = &modes[i];
	if (!m) {
		fprintf(stderr, "modo desconocido: %s\n", argv[1]);
		return EXIT_ERROR;
	}

	fd = open(argv[2], m->open_flags);
	if (fd < 0)
		return report_denied("open", errno);
	if (fstat(fd, &st) != 0 || st.st_size == 0) {
		fprintf(stderr, "el archivo debe existir y no estar vacío\n");
		close(fd);
		return EXIT_ERROR;
	}

	p = mmap(NULL, (size_t)st.st_size, m->prot, m->map_flags, fd, 0);
	if (p == MAP_FAILED) {
		int e = errno;

		close(fd);
		return report_denied("mmap", e);
	}

	if (m->mprotect_to && mprotect(p, (size_t)st.st_size, m->mprotect_to) != 0) {
		int e = errno;

		munmap(p, (size_t)st.st_size);
		close(fd);
		return report_denied("mprotect", e);
	}

	before = p[0]; /* provoca el primer page fault de lectura */
	if (m->write_byte) {
		p[0] = (char)(before == 'X' ? 'Y' : 'X'); /* page fault de escritura */
		if (m->map_flags == MAP_SHARED)
			msync(p, (size_t)st.st_size, MS_SYNC);
	}

	/* Verificar qué quedó en el archivo (por la ruta read(), no por el mapeo) */
	if (pread(fd, &on_disk, 1, 0) == 1 && m->write_byte) {
		if (on_disk == p[0])
			printf("PERMITIDO %s: el archivo FUE modificado ('%c' -> '%c')\n",
			       m->name, before, on_disk);
		else
			printf("PERMITIDO %s: copia privada modificada, archivo intacto (COW)\n",
			       m->name);
	} else {
		printf("PERMITIDO %s\n", m->name);
	}

	munmap(p, (size_t)st.st_size);
	close(fd);
	return EXIT_ALLOWED;
}
