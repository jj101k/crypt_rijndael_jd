#ifndef SRC_CORE_INTERNALS
#define SRC_CORE_INTERNALS

#include <ruby.h>
#include "core-native.h"

/**
 * @brief
 *
 * @param key
 * @param block_len_w
 * @param init
 * @return VALUE
 */
VALUE expand_key_finish(VALUE key, unsigned int block_len_w, struct expandKeyInit init);

#endif /* SRC_CORE_INTERNALS */
