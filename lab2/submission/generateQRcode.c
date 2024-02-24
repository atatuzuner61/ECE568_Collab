#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define BUF 32

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

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	const char * encodedAccountName = urlEncode(accountName);
	const char * encodedIssuer = urlEncode(issuer);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	// Template: otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	uint8_t secret_encoding[BUF];

	// Convert to binary
	uint8_t secret_bin[10];

	int bin_index = 0;
	for (int i = 0; i < strlen(secret_hex); i+=2) {
		uint8_t upper = hex_to_bin_digit(secret_hex[i]);
		uint8_t lower = hex_to_bin_digit(secret_hex[i+1]);
		secret_bin[bin_index++] = (upper << 4) | lower;
	}


	base32_encode(secret_bin, 10, secret_encoding, BUF);

	char uri[256];

	sprintf(uri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, secret_encoding);
	// printf("%s\n", uri);
	displayQRcode(uri);

	return (0);
}
