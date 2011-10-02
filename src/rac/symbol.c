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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "config.h"
#include "util.h"
#include "symbol.h"
#include "log4k.h"
#include "chance.h"

// output a bit to the range encoder, updating bit chance tables
void inline symb_put_bit(symb_coder_t *c, chs_t *chs, int val, uint64_t *count) {
  int chance=chs_get(chs,&c->table);
  rac_put_bit_b16(&c->rac,chance << 4,val);
  if (count) (*count) += log4k[val ? chance : 4096-chance];
  chs_put(chs,&c->table,val);
//  fprintf(stderr,"symb_put_bit: %i with chance %i\n",val,chance);
}

// input a bit from the range decoder, updating bit chance tables
int inline symb_get_bit(symb_coder_t *c, chs_t *chs) {
  int chance=chs_get(chs,&c->table);
  int val = rac_get_bit_b16(&c->rac,chance << 4);
  chs_put(chs,&c->table,val);
//  fprintf(stderr,"symb_get_bit: %i with chance %i\n",val,chance);
  return val;
}

void inline symb_put_simple_bit(symb_coder_t *c, int val, uint64_t *count) {
  rac_put_bit_b16(&c->rac,0x8000,val);
  if (count) (*count)++;
//  fprintf(stderr,"symb_put_bit: %i with chance simple\n",val);
}

int inline symb_get_simple_bit(symb_coder_t *c) {
  int val=rac_get_bit_b16(&c->rac,0x8000);
//  fprintf(stderr,"symb_get_bit: %i with chance simple\n",val);
  return val;
}

// do not output/input anything, but update chance tables anyway
void inline symb_skip_bit(symb_coder_t *c, chs_t *chs, int val) {
  chs_put(chs,&c->table,val);
}

void symb_write_raw(symb_coder_t *c, const void* d, size_t len) {
  const unsigned char *data = d;
  const unsigned char *end = data + len;
  while (data < end) {
    for (int i=7; i>=0; i--)
      rac_put_bit_b16(&c->rac, 0x8000, (*data >> i) & 1);
    data++;
  }
}

void symb_read_raw(symb_coder_t *c, void* d, size_t len) {
  unsigned char *data = d;
  unsigned char *end = data + len;
  while (data < end) {
    *data = 0;
    for (int i=7; i>=0; i--)
      *data |= rac_get_bit_b16(&c->rac, 0x8000) << i;
    data++;
  }
}


// initializer of symbol chance tables when using exponent/mantissa/sign representation
void symb_chs_init(symb_chs_t *sc) {
  chs_init(&sc->chs_zero, 0x800);
  chs_init(&sc->chs_sgn[SYMBOL_BITS-1], 0x800);
  for (int i = 0; i < SYMBOL_BITS-1; i++) {
    chs_init(&sc->chs_exp[i], 0x800);
    chs_init(&sc->chs_sgn[i], 0x800);
    chs_init(&sc->chs_mnt[i], 0x800);
  }
}

static int nbytes = 0;

int static cb_read(void* input) {
  int r = fgetc((FILE*) input);
  nbytes++;
  if (r < 0) return 0;
  return r;
}

void static cb_write(void* output, int data) {
  nbytes++;
  fputc(data,(FILE*) output);
}

void symb_init_read(symb_coder_t *c, FILE* input, int cutoff) {
  chs_table_init(&c->table,cutoff);
  rac_init_dec(&c->rac,cb_read,input);
  nbytes=0;
}

void symb_init_write(symb_coder_t *c, FILE* output, int cutoff) {
  chs_table_init(&c->table,cutoff);
  rac_init_enc(&c->rac,cb_write,output);
  nbytes=0;
}

// statistics
static uint64_t pos = 0, neg = 0, neut = 0;
static int64_t nb_diffs = 0, tot_diffs = 0, tot_sq_diffs = 0;

/* write out a whole symbol to the range encoder using exponent/mantissa/sign representation
 - a zero bit is written if zero is within [min..max]
 - exponent bits are written in unary notation as long as no overflow is implied by them
 - mantissa bits are written only when necessary
 - a sign bit is written if both val and -val are within [min..max]
 */


inline void symb_put_int_limited(symb_coder_t *c, symb_chs_t *sc, int val, int min, int max, uint64_t *count) {
//  fprintf(stderr,"jif_put_symb: %4i in [%4i..%4i]\n",val,min,max);
  // initialization
  assert(min<=max);
  assert(val>=min);
  assert(val<=max);
  if (min == max) return;

  int amax = abs(max) > abs(min) ? abs(max) : abs(min);
  int amin = (max >= 0 && min <= 0) ? 0 : (abs(max) < abs(min) ? abs(max) : abs(min));

  int mymax = 0;
  if (min<0 && max>0) {
        mymax = (val>0 ? abs(max) : abs(min));
  } else {
        mymax = amax;
  }

  
  int bmax = ilog2(amax);
  int bmin = ilog2(amin);

  // statistics
  if (val == 0) {
    neut++;
  } else if (val > 0) {
    pos++;
  } else {
    neg++;
  }
  nb_diffs++;
  tot_diffs += val;
  tot_sq_diffs += val * val;

  if (val) { // nonzero
    const int a = abs(val);
    const int e = ilog2(a);

    // zeroness (chance state 0)
    if (amin == 0) { // zero is possible
      symb_put_bit(c,&sc->chs_zero,0,count);
    }

    // unary encoding of exponent (chance states 1..9)
    assert(e < SYMBOL_BITS);
    int i = bmin;
    while (i < e) {
      symb_put_bit(c,&sc->chs_exp[i],1,count);
      i++;
    }
    if (e < bmax) symb_put_bit(c,&sc->chs_exp[i],0,count);

    // sign (chance states 11..20)
    if (min<0 && max>0) {
      symb_put_bit(c,&sc->chs_sgn[e],val < 0,count);
    }


    // mantissa (chance states 21..29)
    int run = (1 << e);
    int left = (1 << e) - 1;
    for (int i = e-1; i>=0; i--) {
      left ^= (1 << i);
      int bit = 1;
      if (run + (1 << i) > mymax) { // 1-bit would cause overflow
        bit = 0;
        symb_skip_bit(c,&sc->chs_mnt[i],0);
      } else if (run + left < amin) { // 0-bit would cause underflow
        symb_skip_bit(c,&sc->chs_mnt[i],1);
      } else { // both 0 and 1 are possible
        bit = (a >> i) & 1;
        symb_put_bit(c,&sc->chs_mnt[i],bit,count);
      }
      run |= (bit << i);
    }
    val = (val<0?-run:run);


  } else { // zero
    symb_put_bit(c,&sc->chs_zero,1,count);
  }

  assert(val>=min);
  assert(val<=max);
}

void symb_put_int(symb_coder_t *c, symb_chs_t *sc, int val, int min, int max, uint64_t *count) {
   symb_put_int_limited(c,sc, val, min, max, count);
}

// read in a whole symbol from the range encoder using exponent/mantissa/sign representation

inline int symb_get_int_limited(symb_coder_t *c, symb_chs_t *sc, int min, int max) {
  // initialization
  assert(min<=max);
  if (min == max) return min;

  int amax = abs(max) > abs(min) ? abs(max) : abs(min);
  int amin = (max >= 0 && min <= 0) ? 0 : (abs(max) < abs(min) ? abs(max) : abs(min));
  int bmax = ilog2(amax);
  int bmin = ilog2(amin);

  int mymax = 0;

  if (amin == 0 && symb_get_bit(c,&sc->chs_zero)) { // zero
//    fprintf(stderr,"jif_get_symb:    0 in [%4i..%4i]\n",min,max);
    return 0;
  } else { // nonzero
    // unary encoding of exponent
    int e = bmin;
    while (e < bmax && symb_get_bit(c,&sc->chs_exp[e]))
      e++;
    assert(e < SYMBOL_BITS);

    // sign
    int sign = 0;
    if (min<0 && max>0) {
      if (symb_get_bit(c,&sc->chs_sgn[e])) {
        sign = -1;
      } else {
        sign = 1;
      }
    } else {
      sign = 1;
      if (max<=0) sign = -1;
    }


    if (min<0 && max>0) {
          mymax = (sign>0 ? abs(max) : abs(min));
    } else {
          mymax = amax;
    }

    // mantissa
    int run = (1 << e);
    int left = (1 << e) - 1;
    for (int i = e-1; i>=0; i--) {
      left ^= (1 << i);
      int bit = 1;
      if (run + (1 << i) > mymax) { // 1-bit would cause overflow
        bit = 0;
        symb_skip_bit(c,&sc->chs_mnt[i],0);
      } else if (run + left < amin) { // 0-bit would cause underflow
        symb_skip_bit(c,&sc->chs_mnt[i],1);
      } else { // both 0 and 1 are possible
        bit = symb_get_bit(c,&sc->chs_mnt[i]);
      }
      run |= (bit << i);
    }
    int ret = run*sign;

    // output
    if (ret<min || ret>max) fprintf(stderr,"jif_get_symb: %4i in [%4i..%4i]\n",ret,min,max);
    assert(ret>=min);
    assert(ret<=max);
    return ret;
  }
}

int symb_get_int(symb_coder_t *c, symb_chs_t *sc, int min, int max) {
 return symb_get_int_limited(c, sc, min, max);
}

void symb_flush(symb_coder_t *c) {
  rac_flush(&c->rac);
}

void symb_show_stats(FILE *f, symb_coder_t *c) {
/*  fprintf(f,"positive diffs: %llu\n",(unsigned long long) pos);
  fprintf(f,"negative diffs: %llu\n",(unsigned long long) neg);
  fprintf(f,"neutral  diffs: %llu\n",(unsigned long long) neut);
  double avg = 1.0 * tot_diffs / nb_diffs;
  double dev = sqrt(1.0 * tot_sq_diffs / nb_diffs - avg * avg);
  fprintf(f,"diff total: %lli / nb_diffs: %llu  = avg diff: %g (+-%g)\n",(long long) tot_diffs,
      (unsigned long long) nb_diffs,avg,dev); */
  fprintf(f,"bytes read/written: %i\n",nbytes);
  chs_show_stats(f,&c->table);
}
