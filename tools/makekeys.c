#if !TARGET_LPC11XX

#include "ecc.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

extern void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint8_t *p_scalar);

void vli_print(uint8_t *p_vli) {
	unsigned i;

	for(i = 0; i < NUM_ECC_DIGITS - 1; ++i)
		printf("0x%02X, ", (unsigned) p_vli[i]);
	printf("0x%02X", (unsigned) p_vli[i]);
}

int randfd;

void getRandomBytes(void *p_dest, unsigned p_size)
{
	if(read(randfd, p_dest, p_size) != (int)p_size)
		printf("Failed to get random bytes.\n");
}
void usage(char *name) {
	printf("Usage: %s < -f <filename> >\n", name);
	printf("    -f  load test vectors from file\n");
	exit(1);
}

int main(int argc, char **argv)
{
	unsigned i, j;
	int do_file = 0;
	char *filename = NULL;
	FILE *f;

	while ((opt = getopt(argc, argv, "hf:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			break;
		case 'f':
			do_file = 1;
			filename = strdup(optarg);
			break;
		default: /* '?' */
			usage(argv[0]);
		}
	}

	if (!do_file)
		usage(argv[0]);

	f = fopen(filename, "w");
	if (f == NULL) {
		printf("Unable to open %s: %s\n", filename, strerror(errno));
		return 0;
	}

	randfd = open("/dev/urandom", O_RDONLY);
	if(randfd == -1) {
		printf("No access to urandom\n");
		return -1;
	}

	uint8_t l_private[NUM_ECC_DIGITS];
	EccPoint l_public;

	getRandomBytes((char *)l_private, NUM_ECC_DIGITS * sizeof(uint8_t));
	ecc_make_key(&l_public, l_private, l_private);

	printf("uint8_t private_%u[NUM_ECC_DIGITS] = {", i);
	vli_print(l_private);
	printf("};\n");

	printf("EccPoint public_%u = {\n", i);
	printf("    {");
	vli_print(l_public.x);
	printf("},\n");
	printf("    {");
	vli_print(l_public.y);
	printf("}};\n\n");

	return 0;
}

#endif /* !TARGET_LPC11XX */
