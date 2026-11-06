// SPDX-License-Identifier: GPL-2.0
/*
 * bench_mmap.c - Micro-benchmarks para medir el sobrecosto (overhead) que
 * introduce mmap_guard en las rutas de memoria virtual.
 *
 * Uso: bench_mmap <prueba> <archivo> <iteraciones>
 *
 * Pruebas:
 *   mmap      mmap(1 página, PROT_READ, MAP_SHARED) + munmap      -> ns por par
 *             (pasa por security_mmap_file en cada iteración)
 *   mprotect  mprotect(PROT_NONE) + mprotect(PROT_READ) sobre 1 página -> ns por llamada
 *             (pasa por security_file_mprotect en cada llamada)
 *   fault     mapear el archivo completo, tocar 1 byte por página, munmap
 *             -> ns por página; reporta fallos de página menores (getrusage)
 *             (mide la ruta de page fault, que el guard NO intercepta)
 *   read      leer el archivo completo con read() en bloques de 4 KiB -> ns por página
 *   mmapread  mapear el archivo y recorrer TODOS sus bytes            -> ns por página
 *             (read vs mmapread compara copia a buffer vs acceso directo)
 *
 * Salida (CSV, una línea):
 *   prueba,iteraciones,total_ns,ns_por_op,unidad,fallos_menores,fallos_mayores,checksum
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096UL

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

int main(int argc, char **argv)
{
	struct rusage r0, r1;
	struct stat st;
	const char *test;
	uint64_t t0, t1, ops = 0, sum = 0;
	long iters;
	size_t len, pages;
	const char *unit = "op";
	int fd;

	if (argc != 4) {
		fprintf(stderr, "uso: %s <mmap|mprotect|fault|read|mmapread> <archivo> <iteraciones>\n",
			argv[0]);
		return 2;
	}
	test = argv[1];
	iters = atol(argv[3]);

	fd = open(argv[2], O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0)
		die("open");
	len = (size_t)st.st_size;
	pages = (len + PAGE - 1) / PAGE;
	if (len < PAGE) {
		fprintf(stderr, "el archivo debe tener al menos 4 KiB\n");
		return 2;
	}

	/* Calentar el page cache para medir fallos menores, no E/S de disco */
	{
		char *w = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);

		if (w == MAP_FAILED)
			die("mmap (calentamiento)");
		for (size_t i = 0; i < len; i += PAGE)
			sum += (unsigned char)w[i];
		munmap(w, len);
	}

	getrusage(RUSAGE_SELF, &r0);
	t0 = now_ns();

	if (!strcmp(test, "mmap")) {
		for (long i = 0; i < iters; i++) {
			void *p = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);

			if (p == MAP_FAILED)
				die("mmap");
			munmap(p, PAGE);
		}
		ops = (uint64_t)iters;
		unit = "mmap+munmap";
	} else if (!strcmp(test, "mprotect")) {
		char *p = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);

		if (p == MAP_FAILED)
			die("mmap");
		for (long i = 0; i < iters; i++) {
			if (mprotect(p, PAGE, PROT_NONE) || mprotect(p, PAGE, PROT_READ))
				die("mprotect");
		}
		munmap(p, PAGE);
		ops = (uint64_t)iters * 2;
		unit = "mprotect";
	} else if (!strcmp(test, "fault")) {
		for (long i = 0; i < iters; i++) {
			volatile char *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);

			if (p == MAP_FAILED)
				die("mmap");
			for (size_t off = 0; off < len; off += PAGE)
				sum += (unsigned char)p[off];   /* 1 acceso por página */
			munmap((void *)p, len);
		}
		ops = (uint64_t)iters * pages;
		unit = "pagina";
	} else if (!strcmp(test, "read")) {
		char buf[PAGE];

		for (long i = 0; i < iters; i++) {
			ssize_t n;

			if (lseek(fd, 0, SEEK_SET) < 0)
				die("lseek");
			while ((n = read(fd, buf, sizeof(buf))) > 0)
				for (ssize_t k = 0; k + 8 <= n; k += 8) {
					uint64_t v;

					memcpy(&v, buf + k, sizeof(v));
					sum += v;
				}
			if (n < 0)
				die("read");
		}
		ops = (uint64_t)iters * pages;
		unit = "pagina";
	} else if (!strcmp(test, "mmapread")) {
		for (long i = 0; i < iters; i++) {
			const uint64_t *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);

			if (p == MAP_FAILED)
				die("mmap");
			for (size_t k = 0; k < len / 8; k++)
				sum += p[k];
			munmap((void *)p, len);
		}
		ops = (uint64_t)iters * pages;
		unit = "pagina";
	} else {
		fprintf(stderr, "prueba desconocida: %s\n", test);
		return 2;
	}

	t1 = now_ns();
	getrusage(RUSAGE_SELF, &r1);
	close(fd);

	printf("%s,%ld,%llu,%.2f,%s,%ld,%ld,%llu\n", test, iters,
	       (unsigned long long)(t1 - t0), (double)(t1 - t0) / (double)ops, unit,
	       r1.ru_minflt - r0.ru_minflt, r1.ru_majflt - r0.ru_majflt,
	       (unsigned long long)(sum & 0xffff));
	return 0;
}
