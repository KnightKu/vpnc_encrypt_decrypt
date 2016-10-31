/* IPSec VPN client compatible with Cisco equipment.
   Copyright (C) 2004-2007 Maurice Massar
   A bit reorganized in 2007 by Wolfram Sang
   Copyright (C) 2009 Michael Stapelberg

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   $Id$
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <gcrypt.h>

#include "decrypt-utils.h"

/* A SHA-1 digest is 20 bytes long. Why doesn't gcrypt provide this constant? */
#define SHA_DIGEST_LENGTH 20

static int hex2bin_c(unsigned int c)
{
	if ((c >= '0')&&(c <= '9'))
		return c - '0';
	if ((c >= 'A')&&(c <= 'F'))
		return c - 'A' + 10;
	if ((c >= 'a')&&(c <= 'f'))
		return c - 'a' + 10;
	return -1;
}

int hex2bin(const char *str, char **bin, int *len)
{
	char *p;
	int i, l;

	if (!bin)
		return EINVAL;

	for (i = 0; str[i] != '\0'; i++)
		if (hex2bin_c(str[i]) == -1)
			return EINVAL;

	l = i;
	if ((l & 1) != 0)
		return EINVAL;
	l /= 2;

	p = malloc(l);
	if (p == NULL)
		return ENOMEM;

	for (i = 0; i < l; i++)
		p[i] = hex2bin_c(str[i*2]) << 4 | hex2bin_c(str[i*2+1]);

	*bin = p;
	if (len)
		*len = l;

	return 0;
}

static int bin2hex(unsigned const char *input, char *output, int length)
{
	int i;

	for (i = 0; i < length; i++)
		sprintf(output+(2 * i), "%02x", input[i]);

	return (2 * length);
}

/*
 * Deobfuscates a Cisco password. Those are of the following format:
 *
 * -------------------- | -------------------- | 
 * 20 random bytes (ht) |  SHA-1 checksum (h4) | Encrypted data (8 * x bytes)
 * -------------------- | -------------------- |
 *
 */
int deobfuscate(char *ct, int len, const char **resp, char *reslenp)
{
	const char *h1  = ct;
	const char *h4  = ct + 20;
	const char *enc = ct + 40;

	char ht[20], h2[20], h3[20], key[24];
	const char *iv = h1;
	char *res;
	gcry_cipher_hd_t ctx;
	int reslen;

	if (len < 48)
		return -1;
	len -= 40;

	/* ht = first 20 characters */
	memcpy(ht, h1, 20);

	/* Increase the last character */
	ht[19]++;
	/* Build the SHA-1 of ht and store it in h2 */
	gcry_md_hash_buffer(GCRY_MD_SHA1, h2, ht, 20);

	/* Increase the last character by two */
	ht[19] += 2;
	/* Build the SHA-1 of ht and store it in h3 */
	gcry_md_hash_buffer(GCRY_MD_SHA1, h3, ht, 20);

	/* key is the first SHA-1 sum plus the first four characters
	 * of the second SHA-1 sum */
	memcpy(key, h2, 20);
	memcpy(key+20, h3, 4);
	/* who cares about parity anyway? */

	/* Build the SHA-1 of the encrypted part (starting at 40. character) */
	gcry_md_hash_buffer(GCRY_MD_SHA1, ht, enc, len);

	/* Check if checksum is correct */
	if (memcmp(h4, ht, 20) != 0)
		return -1;

	res = malloc(len);
	if (res == NULL)
		return -1;

	gcry_cipher_open(&ctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	/* Key see above */
	gcry_cipher_setkey(ctx, key, 24);
	/* IV are the first 8 bytes of the first block */
	gcry_cipher_setiv(ctx, iv, 8);
	gcry_cipher_decrypt(ctx, (unsigned char *)res, len, (unsigned char *)enc, len);
	gcry_cipher_close(ctx);

	/* Ignore padding bytes */
	reslen = len - res[len-1];
	res[reslen] = '\0';

	if (resp)
		*resp = res;
	if (reslenp)
		*reslenp = reslen;
	return 0;
}

/*
 * Obfuscate the given cleartext in the Cisco format (see deobfuscate())
 *
 */
int obfuscate(char *ct, int len, char **resp, char *resplenp)
{
	uint8_t random_bytes[20];
	uint8_t random_copy[20];
	uint8_t sum1[SHA_DIGEST_LENGTH], sum2[SHA_DIGEST_LENGTH];
	uint8_t key[24];
	uint8_t encrypted[len+16];
	uint8_t input_padded[len+16];
	/* padded_length starts at original length plus one because we
	 * need one byte to store the amount of padded bytes */
	int padded_length = len+1;
	gcry_cipher_hd_t ctx;
	int i, fd;

	/* No output pointer? Why should we even bother encoding then? */
	if (resp == NULL)
		return -1;

	if ((fd = open("/dev/urandom", O_RDONLY)) >= 0) {
		/* Read 20 random bytes from /dev/urandom */
		int bytes_read = 0, ret;
		while (bytes_read < 20) {
			if ((ret = read(fd, random_bytes + bytes_read,
					20 - bytes_read)) < 0)
				return -1;
			bytes_read += ret;
		}
		close(fd);
	} else {
		/* Use standard C PRNG as a fallback */
		srand(time(NULL));
		/* Generate 20 random bytes */
		for (i = 0; i < 20; i++)
			random_bytes[i] = rand();
	}

	/* Create a copy of the bytes */
	memcpy(random_copy, random_bytes, sizeof(random_bytes));

	/* Increase the last byte by one */
	random_copy[19]++;

	/* Build SHA-1 of it (sum1) */
	gcry_md_hash_buffer(GCRY_MD_SHA1, sum1, random_copy, 20);

	/* Increase the last byte by two */
	random_copy[19] += 2;

	/* Build SHA-1 of it (sum2) */
	gcry_md_hash_buffer(GCRY_MD_SHA1, sum2, random_copy, 20);

	/* key = sum1 + sum2[0..3] */
	memcpy(key, sum1, 20);
	memcpy(key+20, sum2, 4);

	/* We need to pad the data to encrypt to a multiple of 8 because
	 * of 3DES requiring a multiple of the block size */
	memset(input_padded, 0, sizeof(input_padded));
	memcpy(input_padded, ct, len);

	while ((padded_length % 8) != 0)
		padded_length++;

	/* Save the amount of padded bytes */
	input_padded[padded_length-1] = (padded_length - len);

	/* encrypt password */
	gcry_cipher_open(&ctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(ctx, key, 24);
	/* iv = random_bytes[0..7] */
	gcry_cipher_setiv(ctx, random_bytes, 8);
	gcry_cipher_encrypt(ctx, encrypted, padded_length, input_padded, padded_length);
	gcry_cipher_close(ctx);

	/* build SHA-1 of that, store it in the beginning */
	gcry_md_hash_buffer(GCRY_MD_SHA1, sum1, encrypted, padded_length);

	/* hex output will require 2 characters per byte */
	char *output;
	output = *resp = calloc(((padded_length + 20 + 20) * 2), sizeof(char));

	/* Format output */
	output += bin2hex(random_bytes, output, SHA_DIGEST_LENGTH);
	output += bin2hex(sum1, output, SHA_DIGEST_LENGTH);
	output += bin2hex(encrypted, output, padded_length);

	if (resplenp != NULL)
		*resplenp = padded_length + 20 + 20;

	return 0;
}
