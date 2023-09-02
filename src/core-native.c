#include <string.h>
#include <stdio.h>
#include "core-native.h"

/*
 * Most of the stuff here deals with the finite field GF(2**8). Don't know what
 * that is? You're not alone; if you want to find out, read the Rijndael spec.
 *
 * The critical thing to note is that a+b in polynomial space is in fact a^b
 * in the binary sense.
 */

/*
 * This is a magic number as far as Rijndael is concerned.
 */
#define POLYNOMIAL_VALUE 0x11b

#define MAX_KEY_WORDS 8
#define MIN_KEY_WORDS 4
#define MAX_BLOCK_WORDS 8

#define WORD_LEN 4
#define MAX_BLOCK_BYTES MAX_BLOCK_WORDS * WORD_LEN

/*
 * Rijndael likes to deal with 'columns', and they're always four bytes high.
 */
#define COLUMN_SIZE 4

#define rounds_by_block_size(a) ((a == 4) ? 10 : (a == 6) ? 12 \
														  : 14)
#define bigger_number(a, b) ((a > b) ? a : b)
#define MAX_ROUND_CONSTANTS_NEEDED (MAX_BLOCK_WORDS * \
									(rounds_by_block_size(MAX_BLOCK_WORDS) + 1) / MIN_KEY_WORDS)
#define SBOX_C 0x63






// The following gets set to 00000000000000000 by default
uint32_t p_round_constant[MAX_ROUND_CONSTANTS_NEEDED];

/*
 * xtime(somebyte)
 *
 * Performs 2*somebyte in GF(2**8) modulo the polynomial 0x011b.
 *
 */
unsigned char xtime(unsigned char inhex)
{
	unsigned short inhex_l = ((unsigned short)inhex) << 1;
	if (inhex_l & 0x100)
		inhex_l ^= 0x1b;
	return (unsigned char)(inhex_l & 0xff);
}

/*
 * poly_div(numerator, denominator)
 *
 * Performs a/b in GF(2**8). As below, this doesn't use our magic polynomial,
 * because it's the reverse of the below operation.
 */

unsigned short poly_div(unsigned short a, unsigned short b)
{
	unsigned short acc = a;
	unsigned short tv = b;
	unsigned short result = 0;
	int i;

	for (i = 7; i >= 0; i--)
	{
		tv = b << i;

		if (((tv & ~acc) < acc) || ((acc ^ tv) <= (1 << i)))
		{
			result |= (1 << i);
			acc ^= tv;
		}
	}
	return result;
}

/*
 * poly_mul(a, b)
 *
 * a*b in GF(2**8). Note that this expands to a series of XOR operations.
 *
 * Not the same as dot() below in that it doesn't do the modulo 0x011b part,
 * nor does it guarantee to return < 256.
 */

unsigned short poly_mul(unsigned short a, unsigned short b)
{
	unsigned short result = 0;
	unsigned short tv = a;
	int i;

	for (i = 0; i < 8; i++)
	{
		if ((b & (1 << i)) > 0)
			result ^= tv;
		tv = tv << 1;
	}
	return result;
}

/*
 * mult_inverse(some number)
 *
 * For an full explanation of a multiplicative inverse, please see the Rijndael
 * spec. For these purposes, all you need to know is that this effectively
 * solves a*POLYNOMIAL=b, where 'b' is supplied. This is not the same as
 * poly_div(), for reasons I forget.
 */

unsigned char mult_inverse(unsigned char num)
{
	unsigned short quotient, multiplied;
	unsigned short remainder[11];
	unsigned short auxiliary[11];
	int i;

	if (!num)
		return 0;

	remainder[0] = POLYNOMIAL_VALUE;
	remainder[1] = num;
	auxiliary[0] = 0;
	auxiliary[1] = 1;

	if (remainder[1] == 1)
		return 1;

	for (i = 2; remainder[i - 1] != 1; i++)
	{
		quotient = poly_div(remainder[i - 2], remainder[i - 1]);
		multiplied = poly_mul(remainder[i - 1], quotient);
		remainder[i] = remainder[i - 2] ^ multiplied;
		auxiliary[i] = poly_mul(quotient, auxiliary[i - 1]) ^ auxiliary[i - 2];
		if (i > 10)
		{
			printf("Sanity failed.\n");
			break;
		}
	}
	return auxiliary[i - 1];
}

/*
 * sbox(somebyte)
 * returns a different byte for each possible value.
 *
 * 'sbox' stands for 'Substitution box' here. This is the part of the cipher
 * that tries to ensure that the output doesn't have bytes in common with the
 * input.
 */
unsigned char sbox(unsigned char somebyte)
{
	somebyte = mult_inverse(somebyte);
	unsigned char result = somebyte;
	unsigned char b_temp;
	int i;

	for (i = 1; i < 5; i++)
	{
		result ^= ((somebyte << i) & 0xff) | (somebyte >> (8 - i));
	}
	return result ^ SBOX_C;
}

/*
 * Caches because the above functions take an age (in CPU operations terms)
 * to do. And hey, we can spare 520-528 bytes, right? Of course we can.
 */
unsigned char sbox_cache[256];
unsigned char inv_sbox_cache[256];

void make_sbox_caches()
{
	int i;
	unsigned char j;
	for (i = 0; i < 256; i++)
	{
		j = sbox(i);
		sbox_cache[i] = j;
		inv_sbox_cache[j] = i;
	}
}

unsigned char *sbox_block(unsigned char *block, size_t length)
{
	size_t i;
	static unsigned char out[MAX_BLOCK_BYTES];
	for (i = 0; i < length; i++)
	{
		out[i] = sbox_cache[block[i]];
	}
	return out;
}

unsigned char dot(unsigned char a, unsigned char b)
{
	unsigned char result = 0;
	unsigned char tv = a;
	int i;
	if (a == 0 || b == 0)
		return 0;
	for (i = 0; i < 8; i++)
	{
		if (b & (1 << i))
			result ^= tv;
		tv = xtime(tv);
	}
	return result;
}

unsigned char *inverse_sbox_block(unsigned char *block, size_t length)
{
	int i;
	static unsigned char out[MAX_BLOCK_BYTES];
	for (i = 0; i < length; i++)
	{
		out[i] = inv_sbox_cache[block[i]];
	}
	return out;
}


/*
 * Another cache, because dot() is used frequently during cipher
 * operations and is, again, expensive.
 *
 * dot_cache is an array of char arrays totalling 4KB plus 68-136 bytes in
 * pointers. Trust me, it's well worth it.
 *
 * Note that we only ever use six values on the left side:
 * 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e
 *
 * We never need 0x01 because the answer is obvious. So, we could shave off much
 * of the 2KB by not generating values we don't need... but I think it's more
 * readable this way (and we can afford to waste 2-3KB and a second on startup,
 * can't we?)
 */
unsigned char *dot_cache[0xf];

unsigned char **make_dot_cache()
{
	int i, j;
	for (i = 0; i < 0xf; i++)
	{
		dot_cache[i] = (unsigned char *)malloc(0x100 * sizeof(unsigned char));
		for (j = 0; j < 0x100; j++)
		{
			dot_cache[i][j] = dot(i, j);
		}
	}
	return dot_cache;
}

/*
 * mix_columns(block string, size in words[quad-bytes])
 *
 * The size in words tells us how many columns there are. This is basically
 * just a matrix operation in GF(2**8) using dot() above to multiply.
 * Each column is run through the matrix.
 *
 * Note that this alters the string in-place, it doesn't create a new one.
 *
 * This is the part of the cipher that performs "bit diffusion".
 */
unsigned char *mix_columns(unsigned char *block, unsigned char block_words)
{
	unsigned char t_column[COLUMN_SIZE];
	int i;
	for (i = 0; i < block_words * COLUMN_SIZE; i += COLUMN_SIZE)
	{
		t_column[0] = dot_cache[02][block[i + 0]] ^
					  dot_cache[03][block[i + 1]] ^
					  block[i + 2] ^
					  block[i + 3];
		t_column[1] = block[i + 0] ^
					  dot_cache[02][block[i + 1]] ^
					  dot_cache[03][block[i + 2]] ^
					  block[i + 3];
		t_column[2] = block[i + 0] ^
					  block[i + 1] ^
					  dot_cache[02][block[i + 2]] ^
					  dot_cache[03][block[i + 3]];
		t_column[3] = dot_cache[03][block[i + 0]] ^
					  block[i + 1] ^
					  block[i + 2] ^
					  dot_cache[02][block[i + 3]];
		memcpy(block + i, t_column, COLUMN_SIZE * sizeof(unsigned char));
	}
	return block;
}

/*
 * As with mix_columns() except it uses an inverted matrix.
 */
unsigned char *inverse_mix_columns(unsigned char *block, unsigned char block_words)
{
	unsigned char t_column[COLUMN_SIZE];
	int i;
	for (i = 0; i < block_words * COLUMN_SIZE; i += COLUMN_SIZE)
	{
		t_column[0] = dot_cache[0x0e][block[i + 0]] ^
					  dot_cache[0x0b][block[i + 1]] ^
					  dot_cache[0x0d][block[i + 2]] ^
					  dot_cache[0x09][block[i + 3]];
		t_column[1] = dot_cache[0x09][block[i + 0]] ^
					  dot_cache[0x0e][block[i + 1]] ^
					  dot_cache[0x0b][block[i + 2]] ^
					  dot_cache[0x0d][block[i + 3]];
		t_column[2] = dot_cache[0x0d][block[i + 0]] ^
					  dot_cache[0x09][block[i + 1]] ^
					  dot_cache[0x0e][block[i + 2]] ^
					  dot_cache[0x0b][block[i + 3]];
		t_column[3] = dot_cache[0x0b][block[i + 0]] ^
					  dot_cache[0x0d][block[i + 1]] ^
					  dot_cache[0x09][block[i + 2]] ^
					  dot_cache[0x0e][block[i + 3]];
		memcpy(block + i, t_column, COLUMN_SIZE * sizeof(unsigned char));
	}
	return block;
}

struct expandKeyInit expand_key_start(uint32_t key_len_b, unsigned int block_len_w, char *key) {
	struct expandKeyInit init;
	init.key_words = key_len_b / WORD_LEN;
	init.rounds = rounds_by_block_size(bigger_number(block_len_w, init.key_words));
	init.round_constants_needed = block_len_w * 4 * (init.rounds + 1) / init.key_words;
	init.expanded_key_words = (uint32_t *)malloc(init.round_constants_needed * key_len_b);
	memcpy(init.expanded_key_words, key, key_len_b);

	return init;
}

struct expandKeyInit expand_key_le6(uint32_t key_len_b, char *key, unsigned int block_len_w)
{
	struct expandKeyInit init = expand_key_start(key_len_b, block_len_w, key);

	int i;

	// Short (128-bit and 192-bit) keys
	for (i = init.key_words; i < block_len_w * (init.rounds + 1); i++)
	{
		uint32_t n_temp = init.expanded_key_words[i - 1];
		if (i % init.key_words == 0)
		{
			// Rotate, sbox, xor
			unsigned char *p_temp = (unsigned char *)&n_temp;
			unsigned char t_byte = p_temp[0];
			p_temp[0] = p_temp[1];
			p_temp[1] = p_temp[2];
			p_temp[2] = p_temp[3];
			p_temp[3] = t_byte;
			p_temp = sbox_block(p_temp, 4);
			memcpy(&n_temp, p_temp, sizeof(n_temp));
			n_temp ^= p_round_constant[i / init.key_words];
		}
		init.expanded_key_words[i] = n_temp ^ init.expanded_key_words[i - init.key_words];
	}

	return init;
}

struct expandKeyInit expand_key_gt6(uint32_t key_len_b, char *key, unsigned int block_len_w)
{
	struct expandKeyInit init = expand_key_start(key_len_b, block_len_w, key);

	int i;

	// Long (256-bit) keys
	for (i = init.key_words; i < block_len_w * (init.rounds + 1); i++)
	{
		uint32_t n_temp = init.expanded_key_words[i - 1];
		if (i % init.key_words == 0)
		{
			// Rotate, xor
			unsigned char *p_temp = (unsigned char *)&n_temp;
			unsigned char t_byte = p_temp[0];
			p_temp[0] = p_temp[1];
			p_temp[1] = p_temp[2];
			p_temp[2] = p_temp[3];
			p_temp[3] = t_byte;

			p_temp = sbox_block(p_temp, 4);
			memcpy(&n_temp, p_temp, sizeof(n_temp));
			n_temp ^= p_round_constant[i / init.key_words];
		}
		else if (i % init.key_words == 4)
		{
			// sbox
			unsigned char *p_temp = sbox_block((unsigned char *)&n_temp, 4);
			memcpy(&n_temp, p_temp, sizeof(n_temp));
		}
		init.expanded_key_words[i] = n_temp ^ init.expanded_key_words[i - init.key_words];
	}

	return init;
}


struct sbl
{
	char block_len;
	char *row_numbers;
};

char *shiftrow_map[256];
char *inv_shiftrow_map[256];

void make_shiftrow_map()
{
	char displace_0_to_3[] = {0, 1, 2, 3};
	char displace_0_2_4[] = {0, 1, 2, 4};
	struct sbl shift_for_block_len[] = {
		{4, displace_0_to_3},
		{6, displace_0_to_3},
		{8, displace_0_2_4}};
	char zero_to_n[256], temp_row[256];
	int i, j, k, m;

	for (i = 0; i < 256; i++)
		zero_to_n[i] = i;
	for (i = 0; i < 3; i++)
	{
		char row_len, block_len;
		row_len = block_len = shift_for_block_len[i].block_len;
		char row_len_bytes = row_len * 4 * sizeof(char);
		char *state_b = malloc(row_len_bytes);
		memcpy(state_b, zero_to_n, row_len_bytes);
		char col_len = 4;
		char *displacements = shift_for_block_len[i].row_numbers;
		for (j = 0; j < col_len; j++)
		{
			/*
			 * This shifts a column or, er, row.
			 */
			if (displacements[j] > 0)
			{
				char displacement_point = row_len - displacements[j];
				/*
				 * We want the stuff after the displacement point first
				 */
				for (m = 0, k = displacement_point; k < row_len; m++, k++)
					temp_row[m] = state_b[j + col_len * k];

				/*
				 * ...and then the stuff before.
				 * Thus ABCDEFG with a displacement of 2 would become
				 * FGABCDE
				 */
				for (m = displacements[j], k = 0; k < displacement_point; m++, k++)
					temp_row[m] = state_b[j + col_len * k];

				/*
				 * We finally store it back in state_b
				 */
				for (k = 0; k < row_len; k++)
					state_b[j + col_len * k] = temp_row[k];
			}
		}
		inv_shiftrow_map[block_len] = state_b;
		shiftrow_map[block_len] = malloc(row_len_bytes);
		for (j = 0; j < row_len_bytes; j++)
			shiftrow_map[block_len][state_b[j]] = j;
	}
}
void make_round_constants()
{
	unsigned char round_constants_needed = MAX_ROUND_CONSTANTS_NEEDED;
	unsigned char temp_v;
	int i;
	for (i = 1, temp_v = 1; i < round_constants_needed; i++, temp_v = dot(02, temp_v))
	{
		*((unsigned char *)(p_round_constant + i)) = temp_v;
	}
}

uint32_t *round0(uint32_t *input_words, uint32_t *round_key_words, unsigned char length_w)
{
	static uint32_t output_words[MAX_KEY_WORDS * 4];
	unsigned char i;
	for (i = 0; i < length_w; i++)
	{
		output_words[i] = input_words[i] ^ round_key_words[i];
	}
	return output_words;
}


char *shift_rows(char *state_b, size_t length_b)
{
	unsigned char length_w = length_b / 4;
	static char state_o[MAX_BLOCK_BYTES];
	int i;
	for (i = 0; i < length_b; i++)
		state_o[i] = state_b[shiftrow_map[length_w][i]];
	return state_o;
}

char *inverse_shift_rows(char *state_b, size_t length_b)
{
	unsigned char length_w = length_b / 4;
	static char state_o[MAX_BLOCK_BYTES];
	int i;
	for (i = 0; i < length_b; i++)
		state_o[i] = state_b[inv_shiftrow_map[length_w][i]];
	return state_o;
}

char *roundn(char *block_bytes, char *round_key_bytes, unsigned char length_b)
{
	block_bytes = (char *)sbox_block((unsigned char *)block_bytes, length_b);
	block_bytes = shift_rows(block_bytes, length_b);
	block_bytes = (char *)mix_columns((unsigned char *)block_bytes, length_b / 4);

	block_bytes = (char *)round0((uint32_t *)block_bytes, (uint32_t *)round_key_bytes, length_b / 4);
	return block_bytes;
}
char *inv_roundn(char *block_bytes, char *round_key_bytes, unsigned char length_b)
{
	block_bytes = (char *)round0((uint32_t *)block_bytes, (uint32_t *)round_key_bytes, length_b / 4);
	block_bytes = (char *)inverse_mix_columns((unsigned char *)block_bytes, length_b / 4);
	block_bytes = inverse_shift_rows(block_bytes, length_b);
	block_bytes = (char *)inverse_sbox_block((unsigned char *)block_bytes, length_b);
	return block_bytes;
}