#include "core-internals.h"

VALUE expand_key_finish(VALUE key, unsigned int block_len_w, struct expandKeyInit init) {
	VALUE expanded_key_a = rb_ary_new2(init.round_constants_needed);
	rb_ary_store(expanded_key_a, 0, key);

	int i;

	for (i = 0; i <= init.rounds; i++)
	{
		rb_ary_store(expanded_key_a, i, rb_str_new((char *)(init.expanded_key_words + i * block_len_w), block_len_w * 4));
	}

	return expanded_key_a;
}