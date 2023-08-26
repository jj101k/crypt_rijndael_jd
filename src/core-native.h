#ifndef SRC_CORE_NATIVE
#define SRC_CORE_NATIVE

#include <stdlib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#include <machine/types.h>
#endif

/**
 * @brief
 *
 */
struct expandKeyInit {
	uint32_t key_words;
	unsigned int rounds;
	unsigned int round_constants_needed;
	uint32_t *expanded_key_words;
};

/**
 * @brief Performs a*b in GF(2**8) modulo our magic polynomial.
 *
 * @param a
 * @param b
 * @return unsigned char
 */
unsigned char dot(unsigned char a, unsigned char b);

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param key_len_b
 * @param key
 * @param block_len_w
 * @return struct expandKeyInit
 */
struct expandKeyInit expand_key_gt6(uint32_t key_len_b, char *key, unsigned int block_len_w);

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param key_len_b
 * @param key
 * @param block_len_w
 * @return struct expandKeyInit
 */
struct expandKeyInit expand_key_le6(uint32_t key_len_b, char *key, unsigned int block_len_w);

/**
 * @brief Applies an inverse sbox to a block
 *
 * @see sbox_block
 *
 * @param block
 * @param length
 * @return unsigned char* - Uses static storage, so results must be copied.
 */
unsigned char *inverse_sbox_block(unsigned char *block, size_t length);

/**
 * @brief
 *
 * @param state_b
 * @param length_b
 * @return char*
 */
char *inverse_shift_rows(char *state_b, size_t length_b);

/**
 * @brief Performs a decryption round
 *
 * @param block_bytes
 * @param round_key_bytes
 * @param length_b
 * @return char*
 */
char *inv_roundn(char *block_bytes, char *round_key_bytes, unsigned char length_b);

/**
 * @brief Create the dot cache!
 *
 * @return unsigned char**
 */
unsigned char **make_dot_cache();

/**
 * @brief
 *
 */
void make_round_constants();

/**
 * @brief Build those caches
 *
 */
void make_sbox_caches();

/**
 * @brief
 *
 */
void make_shiftrow_map();

/**
 * @brief Performs the first round of encryption
 *
 * @param input_words
 * @param round_key_words
 * @param length_w
 * @return uint32_t*
 */
uint32_t *round0(uint32_t *input_words, uint32_t *round_key_words, unsigned char length_w);

/**
 * @brief Performs an encryption round
 *
 * @param block_bytes
 * @param round_key_bytes
 * @param length_b
 * @return char*
 */
char *roundn(char *block_bytes, char *round_key_bytes, unsigned char length_b);

/**
 * @brief Runs the sbox on the block
 *
 * @param block
 * @param length
 * @return unsigned char* - not a string, so no termination here. Same length as
 * "length". Uses static storage, so results must be copied.
 */
unsigned char *sbox_block(unsigned char *block, size_t length);

/**
 * @brief
 *
 * @param state_b
 * @param length_b
 * @return char*
 */
char *shift_rows(char *state_b, size_t length_b);

#endif /* SRC_CORE_NATIVE */
