#include <stdio.h>
#include <liblustre.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

#undef LASSERT
#define LASSERT(cond) if (!(cond)) { printf("failed " #cond "\n"); ret = 1; }

int ret;

void lustre_assert_wire_constants(void);

int main()
{
	lustre_assert_wire_constants();

	if (ret == 0)
		printf("wire constants OK\n");

	return ret;
}

