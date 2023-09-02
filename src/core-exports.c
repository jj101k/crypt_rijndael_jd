#include "core-internals.h"
#include "core-native.h"
#include "core-exports.h"

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param self
 * @param key
 * @param block_len
 * @return VALUE
 */
VALUE cr_c_expand_key_gt6(VALUE self, VALUE key, VALUE block_len)
{
	Check_Type(key, T_STRING);
	Check_Type(block_len, T_FIXNUM);

	uint32_t key_len_b = RSTRING_LEN(key);
	unsigned int block_len_w = NUM2UINT(block_len);

	struct expandKeyInit init = expand_key_gt6(key_len_b, RSTRING_PTR(key), block_len_w);

	return expand_key_finish(key, block_len_w, init);
}

/**
 * @brief This is used to expand the key to blocklen*(rounds+1) bits
 *
 * @param self
 * @param key
 * @param block_len
 * @return VALUE
 */
VALUE cr_c_expand_key_le6(VALUE self, VALUE key, VALUE block_len)
{
	Check_Type(key, T_STRING);
	Check_Type(block_len, T_FIXNUM);

	uint32_t key_len_b = RSTRING_LEN(key);
	unsigned int block_len_w = NUM2UINT(block_len);

	struct expandKeyInit init = expand_key_le6(key_len_b, RSTRING_PTR(key), block_len_w);

	return expand_key_finish(key, block_len_w, init);
}

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_inv_roundl(VALUE self, VALUE input, VALUE round_key)
{
	Check_Type(input, T_STRING);
	Check_Type(round_key, T_STRING);

	unsigned char length_b = RSTRING_LEN(input);
	uint32_t *input_words = (uint32_t *)(RSTRING_PTR(input));
	uint32_t *round_key_words = (uint32_t *)(RSTRING_PTR(round_key));
	char *updated_block = (char *)round0(input_words, round_key_words, length_b / 4);
	updated_block = (char *)inverse_sbox_block((unsigned char *)updated_block, length_b);
	updated_block = inverse_shift_rows(updated_block, length_b);
	input = rb_str_new(updated_block, length_b);
	return input;
}

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_round0(VALUE self, VALUE input, VALUE round_key)
{
	Check_Type(input, T_STRING);
	Check_Type(round_key, T_STRING);
	unsigned char length_w = RSTRING_LEN(input) / 4;
	uint32_t *input_words = (uint32_t *)RSTRING_PTR(input);
	uint32_t *round_key_words = (uint32_t *)RSTRING_PTR(round_key);

	uint32_t *output_words = round0(input_words, round_key_words, length_w);
	VALUE output_s = rb_str_new((char *)output_words, length_w * 4);
	return output_s;
}

/**
 * @brief
 *
 * @param self
 * @param block_words
 * @param key_words
 * @return VALUE
 */
VALUE cr_c_round_count(VALUE self, VALUE block_words, VALUE key_words)
{
	Check_Type(block_words, T_FIXNUM);
	Check_Type(key_words, T_FIXNUM);

	int block_words_i = NUM2INT(block_words);
	int key_words_i = NUM2INT(key_words);
	int biggest_words_i = (block_words_i > key_words_i) ? block_words : key_words;
	int round_count;
	switch (biggest_words_i)
	{
	case 8:
		round_count = 14;
		break;
	case 6:
		round_count = 12;
		break;
	case 4:
		round_count = 10;
		break;
	default:
		rb_raise(rb_eRuntimeError, "Bad word count %d (%d vs %d)", biggest_words_i, block_words_i, key_words_i);
	};
	return INT2NUM(round_count);
}

/**
 * @brief
 *
 * @param self
 * @param input
 * @param round_key
 * @return VALUE
 */
VALUE cr_c_roundl(VALUE self, VALUE input, VALUE round_key)
{
	Check_Type(input, T_STRING);
	Check_Type(round_key, T_STRING);

	unsigned char length_b = RSTRING_LEN(input);
	char *input_bytes = (char *)(RSTRING_PTR(input));
	char *round_key_bytes = (char *)(RSTRING_PTR(round_key));

	char *updated_block = (char *)sbox_block((unsigned char *)input_bytes, length_b);
	updated_block = shift_rows(updated_block, length_b);
	updated_block = (char *)round0((uint32_t *)updated_block, (uint32_t *)round_key_bytes, length_b / 4);
	input = rb_str_new(updated_block, length_b);
	return input;
}

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
VALUE cr_c_roundn_times(VALUE self, VALUE input, VALUE expanded_key, VALUE round_count, VALUE direction)
{
	Check_Type(input, T_STRING);
	Check_Type(expanded_key, T_ARRAY);
	Check_Type(round_count, T_FIXNUM);
	Check_Type(direction, T_SYMBOL);

	unsigned char length_b = RSTRING_LEN(input);
	char *input_bytes = (char *)(RSTRING_PTR(input));
	char round_count_n = NUM2CHR(round_count);
	int i;
	const char *direction_name = rb_id2name(SYM2ID(direction));
	char ix[1000000];

	strncpy(ix, input_bytes, length_b);
	if (!strcmp(direction_name, "reverse"))
	{

		for (i = round_count_n - 1; i > 0; i--)
		{
			VALUE entry = rb_ary_entry(expanded_key, i);
			Check_Type(entry, T_STRING);
			char *r = RSTRING_PTR(entry);
			input_bytes = inv_roundn(input_bytes, r, length_b);
			strncpy(ix, input_bytes, length_b);
		}
	}
	else if (!strcmp(direction_name, "forward"))
	{
		for (i = 1; i < round_count_n; i++)
		{
			VALUE entry = rb_ary_entry(expanded_key, i);
			Check_Type(entry, T_STRING);
			char *r = RSTRING_PTR(entry);
			input_bytes = roundn(input_bytes, r, length_b);
			strncpy(ix, input_bytes, length_b);
		}
	}
	else
	{
		return input; /* FIXME I would rather raise an exception */
	}

	input = rb_str_new(input_bytes, length_b);
	return input;
}