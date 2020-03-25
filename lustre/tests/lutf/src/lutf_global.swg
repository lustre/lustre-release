%module clutf_global

%{
#include <netinet/in.h>
typedef unsigned int bool;
#define true 1
#define false 0
#include "lutf_global.h"
%}

#include "lutf_global.h"

