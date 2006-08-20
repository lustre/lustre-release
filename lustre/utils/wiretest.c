#include <stdio.h>
#include <liblustre.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_disk.h>

#undef LASSERT
#undef LASSERTF
#define CLASSERT(cond) ({ switch(42) { case (cond): case 0: break; } })
#define LASSERT(cond) if (!(cond)) { printf("failed " #cond "\n"); ret = 1; }
#define LASSERTF(cond, fmt, arg) if (!(cond)) { printf("failed '" #cond "'" fmt, arg);ret = 1;}

int ret;

void lustre_assert_wire_constants(void);

int main()
{
        lustre_assert_wire_constants();

        if (ret == 0)
                printf("wire constants OK\n");

        return ret;
}


void lustre_assert_wire_constants(void)
{
}


