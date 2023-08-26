#include <ruby.h>
#include "core-exports.h"
#include "core-internals.h"

/*
 * This class provides essential functions for Rijndael encryption that are
 * expensive to do in Ruby and comfortably fit into C-style procedural code.
 */
void Init_core()
{
	VALUE cCrypt = rb_define_class("JdCrypt", rb_cObject);
	VALUE cCR = rb_define_class_under(cCrypt, "Rijndael", rb_cObject);
	VALUE cCRC = rb_define_class_under(cCR, "Core", rb_cObject);

	rb_define_module_function(cCRC, "expand_key_gt6", cr_c_expand_key_gt6, 2);
	rb_define_module_function(cCRC, "expand_key_le6", cr_c_expand_key_le6, 2);
	rb_define_module_function(cCRC, "inv_roundl", cr_c_inv_roundl, 2);
	rb_define_module_function(cCRC, "round0", cr_c_round0, 2);
	rb_define_module_function(cCRC, "round_count", cr_c_round_count, 2);
	rb_define_module_function(cCRC, "roundl", cr_c_roundl, 2);
	rb_define_module_function(cCRC, "roundn_times", cr_c_roundn_times, 4);

	make_dot_cache();
	make_sbox_caches();
	make_round_constants();
	make_shiftrow_map();
}
