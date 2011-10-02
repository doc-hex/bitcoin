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

#ifndef _CHANCE_H_
#define _CHANCE_H_ 1

#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "log4k.h"

typedef struct {
#if (MULTISCALE_CHANCES == 1)
   uint32_t qual[MULTISCALE_LEVELS]; // estimate of number of bits produced, if corresponding average was used
   uint16_t chance[MULTISCALE_LEVELS]; // chance measured by each average
#else
   uint16_t chance; // use 16-bit integers to represent chances (only 12 bits used)
#endif
} chs_t;

typedef struct {
  int cutoff;
#if (MULTISCALE_CHANCES == 1)
  uint32_t count[MULTISCALE_LEVELS]; // how often each scale was used
  uint16_t next[MULTISCALE_LEVELS][2][4096]; // for each scale, a table to compute the next chance for 0 and 1
#else
  uint16_t next[2][4096]; // just two tables
#endif
} chs_table_t;

void static inline chs_init(chs_t *chs, int chance) {
#if (MULTISCALE_CHANCES == 1)
  for (int i=0; i<MULTISCALE_LEVELS; i++) chs->chance[i]=chance;
  for (int i=0; i<MULTISCALE_LEVELS; i++) chs->qual[i]=0;
#else
  chs->chance=chance;
#endif
}

int static inline chs_get(chs_t *chs, chs_table_t *tbl) {
#if (MULTISCALE_CHANCES == 1)
  int best=0;
  for (int i=1; i<MULTISCALE_LEVELS; i++) { // try all levels
    if (chs->qual[i]<chs->qual[best]) best=i; // find the one with the best bits estimate
  }
  tbl->count[best]++; // update statistics in table
  return chs->chance[best]; // return chance for best one
#else
  return chs->chance;
#endif
}

void static inline chs_put(chs_t *chs, chs_table_t *tbl, int val) {
#if (MULTISCALE_CHANCES == 1)
  for (int i=0; i<MULTISCALE_LEVELS; i++) { // for each scale
    uint64_t sbits=log4k[val ? chs->chance[i] : 4096-chs->chance[i]]; // number of bits if this scale was used
    uint64_t oqual=chs->qual[i]; // previous estimate of bits used for this scale
    chs->qual[i]=(oqual*4095+sbits*65537+2048)/4096; // update bits estimate (([0-2**32-1]*4095+[0..2**16-1]*65537+2048)/4096 = [0..2**32-1])
    chs->chance[i] = tbl->next[i][val][chs->chance[i]]; // update chance
  }
#else
  chs->chance = tbl->next[val][chs->chance];
#endif
}

void chs_table_init(chs_table_t *tbl, int offset);

void chs_show_stats(FILE *f, chs_table_t *tbl);

#endif
