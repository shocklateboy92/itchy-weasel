#pragma once
#ifndef ODPRINTF
#define ODPRINTF

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

void __cdecl odprintf(const char *format, ...);


#endif