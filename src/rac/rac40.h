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

#ifndef RAC40_H_
#define RAC40_H_ 1

#include <stdlib.h>
#include <stdint.h>

typedef uint64_t rac40_t;

typedef struct {
  rac40_t range;
  rac40_t low;
  int delayed_byte;
  int delayed_count;
  void *data;
  void (*writefn)(void *, int);
  int (*readfn)(void *);
} rac40_ctx_t;

void rac40_put_bit_frac(rac40_ctx_t *ctx, int num, int denom, int value);
void rac40_put_bit_b16(rac40_ctx_t *ctx, uint16_t b16, int value);

int rac40_get_bit_frac(rac40_ctx_t *ctx, int num, int denom);
int rac40_get_bit_b16(rac40_ctx_t *ctx, uint16_t b16);

void rac40_init_enc(rac40_ctx_t *ctx, void(*writefn)(void *, int), void *data);
void rac40_init_dec(rac40_ctx_t *ctx, int(*readfn)(void *), void *data);

void rac40_flush(rac40_ctx_t *ctx);

void rac40_build_table(uint16_t *zero_state, uint16_t *one_state, size_t size, int factor, int max_p);

#endif
