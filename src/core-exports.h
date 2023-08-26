#ifndef SRC_CORE_EXPORTS
#define SRC_CORE_EXPORTS

#include <ruby.h>

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param self
 * @param key
 * @param block_len
 * @return VALUE
 */
VALUE cr_c_expand_key_gt6(VALUE self, VALUE key, VALUE block_len);

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param self
 * @param key
 * @param block_len
 * @return VALUE
 */
VALUE cr_c_expand_key_le6(VALUE self, VALUE key, VALUE block_len);

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_inv_roundl(VALUE self, VALUE input, VALUE round_key);

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_round0(VALUE self, VALUE input, VALUE round_key);

/**
 * @brief
 *
 * @param self
 * @param block_words
 * @param key_words
 * @return VALUE
 */
VALUE cr_c_round_count(VALUE self, VALUE block_words, VALUE key_words);

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_roundl(VALUE self, VALUE input, VALUE round_key);

/**
 * @brief
 *
 * @param self
 * @param input
 * @param expanded_key
 * @param round_count
 * @param direction
 * @return VALUE
 */
VALUE cr_c_roundn_times(VALUE self, VALUE input, VALUE expanded_key, VALUE round_count, VALUE direction);

#endif /* SRC_CORE_EXPORTS */
