#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include "lib/sha1.h"
#define IPAD 0x36
#define OPAD 0x5c

uint8_t hex_to_bin_digit(char hex_digit) {
    switch(hex_digit) {
        case '0': return 0b0000;
        case '1': return 0b0001;
        case '2': return 0b0010;
        case '3': return 0b0011;
        case '4': return 0b0100;
        case '5': return 0b0101;
        case '6': return 0b0110;
        case '7': return 0b0111;
        case '8': return 0b1000;
        case '9': return 0b1001;
        case 'A': return 0b1010;
        case 'B': return 0b1011;
        case 'C': return 0b1100;
        case 'D': return 0b1101;
        case 'E': return 0b1110;
        case 'F': return 0b1111;
        default:
            printf("Invalid hexadecimal digit: %c\n", hex_digit);
    }
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Convert to binary and pad to block size with zeros
	uint8_t secret_bin[SHA1_BLOCKSIZE];
	memset(secret_bin, 0, SHA1_BLOCKSIZE);

	int bin_index = 0;
	for (int i = 0; i < strlen(secret_hex); i+=2) {
		uint8_t upper = hex_to_bin_digit(secret_hex[i]);
		uint8_t lower = hex_to_bin_digit(secret_hex[i+1]);
		secret_bin[bin_index++] = ((upper << 4) | lower) & 0xff;
	}

	// Compute inner key
	uint8_t inner_key[SHA1_BLOCKSIZE];
	for (int i = 0; i < SHA1_BLOCKSIZE; i++) {
		inner_key[i] = secret_bin[i] ^ IPAD;
	}

	// Compute outer key
	uint8_t outer_key[SHA1_BLOCKSIZE];
	for (int i = 0; i < SHA1_BLOCKSIZE; i++) {
		outer_key[i] = secret_bin[i] ^ OPAD;
	}

	// Calculate time current Unix time
	uint64_t time64 = (uint64_t)time(NULL)/30;

	uint8_t time8[] = {(time64 >> 56) & 0xff,
						(time64 >> 48) & 0xff,
						(time64 >> 40) & 0xff,
						(time64 >> 32) & 0xff,
						(time64 >> 24) & 0xff,
						(time64 >> 16) & 0xff,
						(time64 >> 8) & 0xff,
						time64 & 0xff};

	// Apply SHA1 hash to inner message
	SHA1_INFO ihash;
	uint8_t isha[SHA1_DIGEST_LENGTH];
	sha1_init(&ihash);
	sha1_update(&ihash, inner_key, SHA1_BLOCKSIZE);
	sha1_update(&ihash, time8, 8);
	sha1_final(&ihash, isha);

	// Apply SHA1 hash to outer message
	SHA1_INFO ohash;
	uint8_t osha[SHA1_DIGEST_LENGTH];
	sha1_init(&ohash);
	sha1_update(&ohash, outer_key, SHA1_BLOCKSIZE);
	sha1_update(&ohash, isha, SHA1_DIGEST_LENGTH);
	sha1_final(&ohash, osha);

	// Truncate result
	int offset   =  osha[19] & 0xf;
	int bin_code = (osha[offset]  & 0x7f) << 24
		| (osha[offset+1] & 0xff) << 16
		| (osha[offset+2] & 0xff) <<  8
		| (osha[offset+3] & 0xff);

	bin_code %= (int)pow(10, 6);

	return bin_code == (int)strtol(TOTP_string, NULL, 10);
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
