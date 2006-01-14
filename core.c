#include <string.h>
#include <stdlib.h>
#include "ruby.h"

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

/*
 * xtime(somebyte)
 * 
 * Performs 2*somebyte in GF(2**8) modulo the polynomial 0x011b.
 *
 */
unsigned char xtime(unsigned char inhex) {
    unsigned short inhex_l=((unsigned short)inhex)<<1;
    if(inhex_l&0x100) inhex_l^=0x1b;
    return (unsigned char)(inhex_l&0xff);
}

/*
 * poly_div(numerator, denominator)
 *
 * Performs a/b in GF(2**8). As below, this doesn't use our magic polynomial,
 * because it's the reverse of the below operation.
 */

unsigned short poly_div(a, b) {
    unsigned short acc=a;
    unsigned short tv=b;
    unsigned short result=0;
    int i;
    
    for(i=7;i>=0;i--) {
        tv=b<<i;

        if( ((tv&~acc) < acc)  || ((acc^tv) <= (1<<i))) {
            result|=(1<<i);
            acc^=tv;
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

unsigned short poly_mul(a, b) {
    unsigned short result=0;
    unsigned short tv=a;
    int i;
    
    for(i=0; i<8; i++) {
        if((b & (1<<i)) > 0) 
            result^=tv;
        tv=tv<<1;
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

unsigned char mult_inverse(unsigned char num) {
    unsigned short quotient, multiplied;
    unsigned short remainder[11];
    unsigned short auxiliary[11];
    int i;
    
    if(!num) return 0;
    
    remainder[0]=POLYNOMIAL_VALUE;
    remainder[1]=num;
    auxiliary[0]=0;
    auxiliary[1]=1;

    if(remainder[1]==1)
       return 1;

    for(i=2;remainder[i-1]!=1;i++) {
        quotient=poly_div(remainder[i-2], remainder[i-1]);
        multiplied=poly_mul(remainder[i-1], quotient);
        remainder[i]=remainder[i-2]^multiplied;
        auxiliary[i]=poly_mul(quotient , auxiliary[i-1]) ^ auxiliary[i-2];
        if (i>10) {
            printf("Sanity failed.\n");
            break;
        }
    }
    return auxiliary[i-1];
}

/*
 * sbox(somebyte)
 * returns a different byte for each possible value.
 *
 * 'sbox' stands for 'Substitution box' here. This is the part of the cipher
 * that tries to ensure that the output doesn't have bytes in common with the
 * input.
 */ 
unsigned char sbox(unsigned char b) {
    unsigned char c=0x63;
    b=mult_inverse(b);
    unsigned char result=b;
    unsigned char b_temp;
    int i;
    
    for(i=1;i<5;i++) {
        b_temp=((b<<i)&0xff)|(b>>(8-i));
        result^=b_temp;
    }
    return result^c;
}

/*
 * Caches because the above functions take an age (in CPU operations terms)
 * to do. And hey, we can spare 520-528 bytes, right? Of course we can.
 */
unsigned char sbox_cache[256];
unsigned char inv_sbox_cache[256];

void make_sbox_caches() {
    int i;
    unsigned char j; 
    for(i=0;i<256;i++) {
        j=sbox(i);
        sbox_cache[i]=j;
        inv_sbox_cache[j]=i;
    }
}

/*
 * Does a block-at-a-time sbox operation. Doesn't care how big the block is,
 * because it doesn't need to.
 *
 * Uses a cache. The output is another string.
 */

static VALUE cr_c_sbox_block(VALUE self, VALUE str) {
    int i;
    unsigned char *i_p=RSTRING(str)->ptr;
    unsigned char *p=(unsigned char *)malloc(RSTRING(str)->len*sizeof(char));
    for(i=0;i<RSTRING(str)->len;i++) {
        p[i]=sbox_cache[i_p[i]];
    }
    VALUE out_str=rb_str_new(p, RSTRING(str)->len);
    free(p);
    return out_str;
}

/*
 * Reverses the above operation, for decryption purposes.
 */

static VALUE cr_c_inverse_sbox_block(VALUE self, VALUE str) {
    int i;
    unsigned char *i_p=RSTRING(str)->ptr;
    unsigned char *p=(unsigned char *)malloc(RSTRING(str)->len*sizeof(char));
    for(i=0;i<RSTRING(str)->len;i++) {
        p[i]=inv_sbox_cache[i_p[i]];
    }
    VALUE out_str=rb_str_new(p, RSTRING(str)->len);
    free(p);
    return out_str;
}

/*
 * Rijndael likes to deal with 'columns', and they're always four bytes high.
 */
#define COLUMN_SIZE 4


/*
 * dot(a, b)
 *
 * Performs a*b in GF(2**8) modulo our magic polynomial.
 */
unsigned char dot(unsigned char a, unsigned char b) {
    unsigned char result=0;
    unsigned char tv=a;
    int i;
    if(a==0 || b==0) return 0;
    for(i=0;i<8;i++) {
        if(b & (1<<i))
            result^=tv;
        tv=xtime(tv);
    }
    return result;
}

/*
 * Performs a*b in GF(2**8) modulo our magic polynomial.
 */
VALUE cr_c_dot(VALUE self, VALUE a, VALUE b) {
    return CHR2FIX(dot(NUM2CHR(a), NUM2CHR(b)));
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

unsigned char **make_dot_cache() {
    int i,j;
    for(i=0;i<0x10;i++) {
        dot_cache[i]=(char *)malloc(256*sizeof(unsigned char));
        for(j=0;j<0x100;j++) {
            dot_cache[i][j]=dot(i,j);
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
unsigned char *mix_columns(unsigned char *in_block, unsigned char block_words) {
    unsigned char t_column[COLUMN_SIZE];
    int i;
    for(i=0;i<block_words*COLUMN_SIZE;i+=COLUMN_SIZE) {
        t_column[0]=dot_cache[02][in_block[i+0]] ^
            dot_cache[03][in_block[i+1]] ^
            in_block[i+2] ^
            in_block[i+3];
        t_column[1]=in_block[i+0] ^
            dot_cache[02][in_block[i+1]] ^
            dot_cache[03][in_block[i+2]] ^
            in_block[i+3];
        t_column[2]=in_block[i+0] ^
            in_block[i+1] ^
            dot_cache[02][in_block[i+2]] ^
            dot_cache[03][in_block[i+3]];
        t_column[3]=dot_cache[03][in_block[i+0]] ^
            in_block[i+1] ^
            in_block[i+2] ^
            dot_cache[02][in_block[i+3]];
        memcpy(in_block+i, t_column, COLUMN_SIZE*sizeof(unsigned char));
    }
    return in_block;
}

/*
 * As with mix_columns() except it uses an inverted matrix.
 */
unsigned char *inverse_mix_columns(unsigned char *in_block, unsigned char block_words) {
    unsigned char t_column[COLUMN_SIZE];
    int i;
    for(i=0;i<block_words*COLUMN_SIZE;i+=COLUMN_SIZE) {
        t_column[0]=dot_cache[0x0e][in_block[i+0]] ^
            dot_cache[0x0b][in_block[i+1]] ^
            dot_cache[0x0d][in_block[i+2]] ^
            dot_cache[0x09][in_block[i+3]];
        t_column[1]=dot_cache[0x09][in_block[i+0]] ^
            dot_cache[0x0e][in_block[i+1]] ^
            dot_cache[0x0b][in_block[i+2]] ^
            dot_cache[0x0d][in_block[i+3]];
        t_column[2]=dot_cache[0x0d][in_block[i+0]] ^
            dot_cache[0x09][in_block[i+1]] ^
            dot_cache[0x0e][in_block[i+2]] ^
            dot_cache[0x0b][in_block[i+3]];
        t_column[3]=dot_cache[0x0b][in_block[i+0]] ^
            dot_cache[0x0d][in_block[i+1]] ^
            dot_cache[0x09][in_block[i+2]] ^
            dot_cache[0x0e][in_block[i+3]];
        memcpy(in_block+i, t_column, COLUMN_SIZE*sizeof(unsigned char));
    }
    return in_block;
}

/*
 * This is basically just a matrix operation in GF(2**8).
 * Each column is run through the matrix.
 *
 * This is the part of the cipher that performs "bit diffusion".
 */
static VALUE cr_c_mix_column(VALUE self, VALUE in_block) {
    volatile VALUE str=in_block;
    char *p=(char *)malloc(RSTRING(str)->len*sizeof(char));
    memcpy(p, RSTRING(str)->ptr, RSTRING(str)->len);
    mix_columns(p, RSTRING(str)->len/COLUMN_SIZE);
    VALUE out_str=rb_str_new(p, RSTRING(str)->len);
    free(p);
    return out_str;
}

/*
 * As with mix_column() except it uses an inverted matrix.
 */
 
static VALUE cr_c_inverse_mix_column(VALUE self, VALUE in_block) {
    volatile VALUE str=in_block;
    char *p=(char *)malloc(RSTRING(str)->len*sizeof(char));
    memcpy(p, RSTRING(str)->ptr, RSTRING(str)->len);
    inverse_mix_columns(p, RSTRING(str)->len/COLUMN_SIZE);
    VALUE out_str=rb_str_new(p, RSTRING(str)->len);
    free(p);
    return out_str;
}

/*
 * This class provides essential functions for Rijndael encryption that are expensive to do in Ruby
 * and comfortably fit into C-style procedural code.
 */
void Init_core() {
    VALUE cCrypt=rb_define_class("Crypt", rb_cObject);
    VALUE cCR=rb_define_class_under(cCrypt, "Rijndael", rb_cObject);
    VALUE cFoo=rb_define_class_under(cCR, "Core", rb_cObject);
    rb_define_module_function(cFoo, "mix_column", cr_c_mix_column, 1);
    rb_define_module_function(cFoo, "inv_mix_column", cr_c_inverse_mix_column, 1);
    rb_define_module_function(cFoo, "sbox_block", cr_c_sbox_block, 1);
    rb_define_module_function(cFoo, "inv_sbox_block", cr_c_inverse_sbox_block, 1);
    rb_define_module_function(cFoo, "dot", cr_c_dot, 2);
    make_dot_cache();
    make_sbox_caches();
}
