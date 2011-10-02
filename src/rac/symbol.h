/*  Copyright (C) 2010-2010  Jon Sneyers & Pieter Wuille

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 Parts of this code are based on code from the FFMPEG project, in
 particular:
 - rangecoder.c - Copyright (c) 2004 Michael Niedermayer <michaelni@gmx.at>
 - ffv1.c - Copyright (c) 2004 Michael Niedermayer <michaelni@gmx.at>
 */

#ifndef _SYMBOL_H_
#define _SYMBOL_H_ 1

#include <stdio.h>
#include "config.h"
#include "chance.h"

#if (RAC_BITS == 40)
#include "rac40.h"
#define rac_ctx_t         rac40_ctx_t
#define rac_put_bit_b16   rac40_put_bit_b16
#define rac_get_bit_b16   rac40_get_bit_b16
#define rac_put_bit_frac  rac40_put_bit_frac
#define rac_get_bit_frac  rac40_get_bit_frac
#define rac_init_enc      rac40_init_enc
#define rac_init_dec      rac40_init_dec
#define rac_flush         rac40_flush
#endif

#if (RAC_BITS == 24)
#include "rac24.h"
#define rac_ctx_t         rac24_ctx_t
#define rac_put_bit_b16   rac24_put_bit_b16
#define rac_get_bit_b16   rac24_get_bit_b16
#define rac_put_bit_frac  rac24_put_bit_frac
#define rac_get_bit_frac  rac24_get_bit_frac
#define rac_init_enc      rac24_init_enc
#define rac_init_dec      rac24_init_dec
#define rac_flush         rac24_flush
#endif

#if (RAC_BITS == 16)
#include "rac16.h"
#define rac_ctx_t         rac16_ctx_t
#define rac_put_bit_b16   rac16_put_bit_b16
#define rac_get_bit_b16   rac16_get_bit_b16
#define rac_put_bit_frac  rac16_put_bit_frac
#define rac_get_bit_frac  rac16_get_bit_frac
#define rac_init_enc      rac16_init_enc
#define rac_init_dec      rac16_init_dec
#define rac_flush         rac16_flush
#endif

// normal symbol chance tables use exponent/mantissa/sign counters
typedef struct {
  chs_t chs_zero;
  chs_t chs_exp[SYMBOL_BITS-1];
  chs_t chs_sgn[SYMBOL_BITS];
  chs_t chs_mnt[SYMBOL_BITS-1];
} symb_chs_t;

typedef struct {
  chs_table_t table;
  rac_ctx_t rac;
} symb_coder_t;

void symb_chs_init(symb_chs_t *sc);
void symb_init_write(symb_coder_t *c, FILE* output, int cutoff);
void symb_init_read(symb_coder_t *c, FILE* input, int cutoff);
void symb_skip_bit(symb_coder_t *c, chs_t *chs, int val);
void symb_put_bit(symb_coder_t *c, chs_t *chs, int val, uint64_t *count);
int symb_get_bit(symb_coder_t *c, chs_t *chs);
void symb_write_raw(symb_coder_t *c, const void* data, size_t len);
void symb_read_raw(symb_coder_t *c, void* data, size_t len);
void symb_put_simple_bit(symb_coder_t *c, int val, uint64_t *count);
int symb_get_simple_bit(symb_coder_t *c);
void symb_put_int(symb_coder_t *c, symb_chs_t *sc, int val, int min, int max, uint64_t *count);
int symb_get_int(symb_coder_t *c, symb_chs_t *sc, int min, int max);
void symb_put_int_limited(symb_coder_t *c, symb_chs_t *sc, int val, int min, int max, uint64_t *count);
int symb_get_int_limited(symb_coder_t *c, symb_chs_t *sc, int min, int max);
void symb_flush(symb_coder_t *c);
void symb_show_stats(FILE *f, symb_coder_t *c);

#endif
