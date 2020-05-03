#include "lzokay.h"
#include <string.h>
#include <limits.h>
#include <stdbool.h>

static uint8_t* std_mismatch(uint8_t* first1, uint8_t* last1, uint8_t* first2)
{
    while (first1 != last1 && *first1 == *first2) {
        ++first1, ++first2;
    }
    return first1;
}

/*
 * Based on documentation from the Linux sources: Documentation/lzo.txt
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/lzo.txt
 */

#if _WIN32
#define HOST_BIG_ENDIAN 0
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HOST_BIG_ENDIAN 1
#else
#define HOST_BIG_ENDIAN 0
#endif

#ifndef min
# define min(x,y)  ((x)>(y)?(y):(x))
#endif

#ifndef max
# define max(x,y)  ((x)<(y)?(y):(x))
#endif

#if HOST_BIG_ENDIAN
static uint16_t get_le16(const uint8_t* p) {
  uint16_t val = *reinterpret_cast<const uint16_t*>(p);
#if __GNUC__
  return __builtin_bswap16(val);
#elif _WIN32
  return _byteswap_ushort(val);
#else
  return (val = (val << 8) | ((val >> 8) & 0xFF));
#endif
}
#else
static uint16_t get_le16(const uint8_t* p) {
  return *(const uint16_t*)p;
}
#endif

static const size_t Max255Count = SIZE_MAX / 255 - 2;

#define NEEDS_IN(count) \
  if (inp + (count) > inp_end) { \
    *dst_size = outp - dst; \
    return EResult_InputOverrun; \
  }

#define NEEDS_OUT(count) \
  if (outp + (count) > outp_end) { \
    *dst_size = outp - dst; \
    return EResult_OutputOverrun; \
  }

#define CONSUME_ZERO_BYTE_LENGTH \
  size_t offset; \
  { \
    const uint8_t *old_inp = inp; \
    while (*inp == 0) ++inp; \
    offset = inp - old_inp; \
    if (offset > Max255Count) { \
      *dst_size = outp - dst; \
      return EResult_Error; \
    } \
  }

#define WRITE_ZERO_BYTE_LENGTH(length) \
  { \
    uint32_t l; \
    for (l = length; l > 255; l -= 255) { *outp++ = 0; } \
    *outp++ = l; \
  }

static const uint32_t M1MaxOffset = 0x0400;
static const uint32_t M2MaxOffset = 0x0800;
static const uint32_t M3MaxOffset = 0x4000;
static const uint32_t M4MaxOffset = 0xbfff;

static const uint32_t M1MinLen = 2;
static const uint32_t M1MaxLen = 2;
static const uint32_t M2MinLen = 3;
static const uint32_t M2MaxLen = 8;
static const uint32_t M3MinLen = 3;
static const uint32_t M3MaxLen = 33;
static const uint32_t M4MinLen = 3;
static const uint32_t M4MaxLen = 9;

static const uint32_t M1Marker = 0x0;
static const uint32_t M2Marker = 0x40;
static const uint32_t M3Marker = 0x20;
static const uint32_t M4Marker = 0x10;

#define MaxMatchByLengthLen 34 /* Max M3 len + 1 */

lzokay_EResult lzokay_decompress(const uint8_t* src, size_t src_size,
                   uint8_t* dst, size_t init_dst_size,
                   size_t *dst_size) {
  *dst_size = init_dst_size;

  if (src_size < 3) {
    *dst_size = 0;
    return EResult_InputOverrun;
  }

  const uint8_t* inp = src;
  const uint8_t* inp_end = src + src_size;
  uint8_t* outp = dst;
  uint8_t* outp_end = dst + *dst_size;
  uint8_t* lbcur;
  size_t lblen;
  size_t state = 0;
  size_t nstate = 0;

  /* First byte encoding */
  if (*inp >= 22) {
    /* 22..255 : copy literal string
     *           length = (byte - 17) = 4..238
     *           state = 4 [ don't copy extra literals ]
     *           skip byte
     */
    size_t len = *inp++ - (uint8_t)(17);
    NEEDS_IN(len)
    NEEDS_OUT(len)
    for (size_t i = 0; i < len; ++i)
      *outp++ = *inp++;
    state = 4;
  } else if (*inp >= 18) {
    /* 18..21 : copy 0..3 literals
     *          state = (byte - 17) = 0..3  [ copy <state> literals ]
     *          skip byte
     */
    nstate = *inp++ - (uint8_t)(17);
    state = nstate;
    NEEDS_IN(nstate)
    NEEDS_OUT(nstate)
    for (size_t i = 0; i < nstate; ++i)
      *outp++ = *inp++;
  }
  /* 0..17 : follow regular instruction encoding, see below. It is worth
   *         noting that codes 16 and 17 will represent a block copy from
   *         the dictionary which is empty, and that they will always be
   *         invalid at this place.
   */

  while (true) {
    NEEDS_IN(1)
    uint8_t inst = *inp++;
    if (inst & 0xC0) {
      /* [M2]
       * 1 L L D D D S S  (128..255)
       *   Copy 5-8 bytes from block within 2kB distance
       *   state = S (copy S literals after this block)
       *   length = 5 + L
       * Always followed by exactly one byte : H H H H H H H H
       *   distance = (H << 3) + D + 1
       *
       * 0 1 L D D D S S  (64..127)
       *   Copy 3-4 bytes from block within 2kB distance
       *   state = S (copy S literals after this block)
       *   length = 3 + L
       * Always followed by exactly one byte : H H H H H H H H
       *   distance = (H << 3) + D + 1
       */
      NEEDS_IN(1)
      lbcur = outp - ((*inp++ << 3) + ((inst >> 2) & 0x7) + 1);
      lblen = (size_t)(inst >> 5) + 1;
      nstate = inst & (uint8_t)(0x3);
    } else if (inst & M3Marker) {
      /* [M3]
       * 0 0 1 L L L L L  (32..63)
       *   Copy of small block within 16kB distance (preferably less than 34B)
       *   length = 2 + (L ?: 31 + (zero_bytes * 255) + non_zero_byte)
       * Always followed by exactly one LE16 :  D D D D D D D D : D D D D D D S S
       *   distance = D + 1
       *   state = S (copy S literals after this block)
       */
      lblen = (size_t)(inst & (uint8_t)(0x1f)) + 2;
      if (lblen == 2) {
        CONSUME_ZERO_BYTE_LENGTH
        NEEDS_IN(1)
        lblen += offset * 255 + 31 + *inp++;
      }
      NEEDS_IN(2)
      nstate = get_le16(inp);
      inp += 2;
      lbcur = outp - ((nstate >> 2) + 1);
      nstate &= 0x3;
    } else if (inst & M4Marker) {
      /* [M4]
       * 0 0 0 1 H L L L  (16..31)
       *   Copy of a block within 16..48kB distance (preferably less than 10B)
       *   length = 2 + (L ?: 7 + (zero_bytes * 255) + non_zero_byte)
       * Always followed by exactly one LE16 :  D D D D D D D D : D D D D D D S S
       *   distance = 16384 + (H << 14) + D
       *   state = S (copy S literals after this block)
       *   End of stream is reached if distance == 16384
       */
      lblen = (size_t)(inst & (uint8_t)(0x7)) + 2;
      if (lblen == 2) {
        CONSUME_ZERO_BYTE_LENGTH
        NEEDS_IN(1)
        lblen += offset * 255 + 7 + *inp++;
      }
      NEEDS_IN(2)
      nstate = get_le16(inp);
      inp += 2;
      lbcur = outp - (((inst & 0x8) << 11) + (nstate >> 2));
      nstate &= 0x3;
      if (lbcur == outp)
        break; /* Stream finished */
      lbcur -= 16384;
    } else {
      /* [M1] Depends on the number of literals copied by the last instruction. */
      if (state == 0) {
        /* If last instruction did not copy any literal (state == 0), this
         * encoding will be a copy of 4 or more literal, and must be interpreted
         * like this :
         *
         *    0 0 0 0 L L L L  (0..15)  : copy long literal string
         *    length = 3 + (L ?: 15 + (zero_bytes * 255) + non_zero_byte)
         *    state = 4  (no extra literals are copied)
         */
        size_t len = inst + 3;
        if (len == 3) {
          CONSUME_ZERO_BYTE_LENGTH
          NEEDS_IN(1)
          len += offset * 255 + 15 + *inp++;
        }
        /* copy_literal_run */
        NEEDS_IN(len)
        NEEDS_OUT(len)
        for (size_t i = 0; i < len; ++i)
          *outp++ = *inp++;
        state = 4;
        continue;
      } else if (state != 4) {
        /* If last instruction used to copy between 1 to 3 literals (encoded in
         * the instruction's opcode or distance), the instruction is a copy of a
         * 2-byte block from the dictionary within a 1kB distance. It is worth
         * noting that this instruction provides little savings since it uses 2
         * bytes to encode a copy of 2 other bytes but it encodes the number of
         * following literals for free. It must be interpreted like this :
         *
         *    0 0 0 0 D D S S  (0..15)  : copy 2 bytes from <= 1kB distance
         *    length = 2
         *    state = S (copy S literals after this block)
         *  Always followed by exactly one byte : H H H H H H H H
         *    distance = (H << 2) + D + 1
         */
        NEEDS_IN(1)
        nstate = inst & (uint8_t)(0x3);
        lbcur = outp - ((inst >> 2) + (*inp++ << 2) + 1);
        lblen = 2;
      } else {
        /* If last instruction used to copy 4 or more literals (as detected by
         * state == 4), the instruction becomes a copy of a 3-byte block from the
         * dictionary from a 2..3kB distance, and must be interpreted like this :
         *
         *    0 0 0 0 D D S S  (0..15)  : copy 3 bytes from 2..3 kB distance
         *    length = 3
         *    state = S (copy S literals after this block)
         *  Always followed by exactly one byte : H H H H H H H H
         *    distance = (H << 2) + D + 2049
         */
        NEEDS_IN(1)
        nstate = inst & (uint8_t)(0x3);
        lbcur = outp - ((inst >> 2) + (*inp++ << 2) + 2049);
        lblen = 3;
      }
    }
    if (lbcur < dst) {
      *dst_size = outp - dst;
      return EResult_LookbehindOverrun;
    }
    NEEDS_IN(nstate)
    NEEDS_OUT(lblen + nstate)
    /* Copy lookbehind */
    for (size_t i = 0; i < lblen; ++i)
      *outp++ = *lbcur++;
    state = nstate;
    /* Copy literal */
    for (size_t i = 0; i < nstate; ++i)
      *outp++ = *inp++;
  }

  *dst_size = outp - dst;
  if (lblen != 3) /* Ensure terminating M4 was encountered */
    return EResult_Error;
  if (inp == inp_end)
    return EResult_Success;
  else if (inp < inp_end)
    return EResult_InputNotConsumed;
  else
    return EResult_InputOverrun;
}

struct State {
  const uint8_t* src;
  const uint8_t* src_end;
  const uint8_t* inp;
  uint32_t wind_sz;
  uint32_t wind_b;
  uint32_t wind_e;
  uint32_t cycle1_countdown;

  const uint8_t* bufp;
  uint32_t buf_sz;
};

/* Access next input byte and advance both ends of circular buffer */
void get_byte(struct State *s, uint8_t* buf) {
  if (s->inp >= s->src_end) {
    if (s->wind_sz > 0)
      --s->wind_sz;
    buf[s->wind_e] = 0;
    if (s->wind_e < DictBase_MaxMatchLen)
      buf[DictBase_BufSize + s->wind_e] = 0;
  } else {
    buf[s->wind_e] = *s->inp;
    if (s->wind_e < DictBase_MaxMatchLen)
      buf[DictBase_BufSize + s->wind_e] = *s->inp;
    ++s->inp;
  }
  if (++s->wind_e == DictBase_BufSize)
    s->wind_e = 0;
  if (++s->wind_b == DictBase_BufSize)
    s->wind_b = 0;
}

uint32_t pos2off(const struct State *s, uint32_t pos) {
  return s->wind_b > pos ? s->wind_b - pos : DictBase_BufSize - (pos - s->wind_b);
}

static uint32_t Match3_make_key(const uint8_t* data) {
  return ((0x9f5f * ((((uint32_t)(data[0]) << 5 ^ (uint32_t)(data[1])) << 5) ^ data[2])) >> 5) & 0x3fff;
}

static uint16_t Match3_get_head(const struct Match3 *match, uint32_t key) {
  return (match->chain_sz[key] == 0) ? (uint16_t)(UINT16_MAX) : match->head[key];
}

static void Match3_init(struct Match3 *match) {
  memset(match->chain_sz, 0, sizeof(match->chain_sz));
}

static void Match3_remove(struct Match3 *match, uint32_t pos, const uint8_t* b) {
  --match->chain_sz[Match3_make_key(b + pos)];
}

static void Match3_advance(struct Match3 *match, struct State* s, uint32_t *match_pos, uint32_t *match_count, const uint8_t* b) {
  uint32_t key = Match3_make_key(b + s->wind_b);
  *match_pos = match->chain[s->wind_b] = Match3_get_head(match, key);
  *match_count = match->chain_sz[key]++;
  if (*match_count > DictBase_MaxMatchLen)
    *match_count = DictBase_MaxMatchLen;
  match->head[key] = (uint16_t)(s->wind_b);
}

static void Match3_skip_advance(struct Match3 *match, struct State* s, const uint8_t* b) {
  uint32_t key = Match3_make_key(b + s->wind_b);
  match->chain[s->wind_b] = Match3_get_head(match, key);
  match->head[key] = (uint16_t)(s->wind_b);
  match->best_len[s->wind_b] = (uint16_t)(DictBase_MaxMatchLen + 1);
  match->chain_sz[key]++;
}

static uint32_t Match2_make_key(const uint8_t* data) {
  return (uint32_t)(data[0]) ^ ((uint32_t)(data[1]) << 8);
}

static void Match2_init(struct Match2 *match) {
  for (size_t i=0; i<(sizeof(match->head)/sizeof(match->head[0])); ++i)
    match->head[i] = UINT16_MAX;
}

static void Match2_add(struct Match2 *match, uint16_t pos, const uint8_t* b) {
  match->head[Match2_make_key(b + pos)] = pos;
}

static void Match2_remove(struct Match2 *match, uint32_t pos, const uint8_t* b) {
  uint16_t *p = &match->head[Match2_make_key(b + pos)];
  if (*p == pos)
    *p = UINT16_MAX;
}

static bool Match2_search(const struct Match2 *match, struct State* s, uint32_t *lb_pos, uint32_t *lb_len,
                          uint32_t best_pos[MaxMatchByLengthLen], const uint8_t* b) {
  uint16_t pos = match->head[Match2_make_key(b + s->wind_b)];
  if (pos == UINT16_MAX)
    return false;
  if (best_pos[2] == 0)
    best_pos[2] = pos + 1;
  if (*lb_len < 2) {
    *lb_len = 2;
    *lb_pos = pos;
  }
  return true;
}

static void Dict_init(struct lzokay_Dict *dict, struct State* s, const uint8_t* src, size_t src_size) {
  s->cycle1_countdown = DictBase_MaxDist;
  Match3_init(&dict->match3);
  Match2_init(&dict->match2);

  s->src = src;
  s->src_end = src + src_size;
  s->inp = src;
  s->wind_sz = min((uint32_t)src_size, DictBase_MaxMatchLen);
  s->wind_b = 0;
  s->wind_e = s->wind_sz;
  memcpy(dict->buffer, s->inp, s->wind_sz);
  s->inp += s->wind_sz;

  if (s->wind_e == DictBase_BufSize)
    s->wind_e = 0;

  if (s->wind_sz < 3)
    memset(&dict->buffer[s->wind_b + s->wind_sz], 0, 3);
}

static void Dict_reset_next_input_entry(struct lzokay_Dict *dict, struct State* s, struct Match3* match3, struct Match2* match2) {
  /* Remove match from about-to-be-clobbered buffer entry */
  if (s->cycle1_countdown == 0) {
    Match3_remove(match3, s->wind_e, dict->buffer);
    Match2_remove(match2, s->wind_e, dict->buffer);
  } else {
    --s->cycle1_countdown;
  }
}

static void Dict_advance(struct lzokay_Dict *dict, struct State* s, uint32_t *lb_off, uint32_t *lb_len,
              uint32_t best_off[MaxMatchByLengthLen], bool skip) {
  if (skip) {
    for (uint32_t i = 0; i < *lb_len - 1; ++i) {
      Dict_reset_next_input_entry(dict, s, &dict->match3, &dict->match2);
      Match3_skip_advance(&dict->match3, s, dict->buffer);
      Match2_add(&dict->match2, (uint16_t)(s->wind_b), dict->buffer);
      get_byte(s, dict->buffer);
    }
  }

  *lb_len = 1;
  *lb_off = 0;
  uint32_t lb_pos;

  uint32_t best_pos[MaxMatchByLengthLen] = {0};
  uint32_t match_pos, match_count;
  Match3_advance(&dict->match3, s, &match_pos, &match_count, dict->buffer);

  int best_char = dict->buffer[s->wind_b];
  uint32_t best_len = *lb_len;
  if (*lb_len >= s->wind_sz) {
    if (s->wind_sz == 0)
      best_char = -1;
    *lb_off = 0;
    dict->match3.best_len[s->wind_b] = DictBase_MaxMatchLen + 1;
  } else {
    if (Match2_search(&dict->match2, s, &lb_pos, lb_len, best_pos, dict->buffer) && s->wind_sz >= 3) {
      for (uint32_t i = 0; i < match_count; ++i, match_pos = dict->match3.chain[match_pos]) {
        uint8_t *ref_ptr = dict->buffer + s->wind_b;
        uint8_t *match_ptr = dict->buffer + match_pos;
        uint8_t *mismatch = std_mismatch(ref_ptr, ref_ptr + s->wind_sz, match_ptr);
        intptr_t match_len = mismatch - ref_ptr;
        if (match_len < 2)
          continue;
        if (match_len < MaxMatchByLengthLen && best_pos[match_len] == 0)
          best_pos[match_len] = match_pos + 1;
        if (match_len > *lb_len) {
          *lb_len = match_len;
          lb_pos = match_pos;
          if (match_len == s->wind_sz || match_len > dict->match3.best_len[match_pos])
            break;
        }
      }
    }
    if (*lb_len > best_len)
      *lb_off = pos2off(s, lb_pos);
    dict->match3.best_len[s->wind_b] = (uint16_t)(*lb_len);
    const uint32_t *end_best_pos = &best_pos[sizeof(best_pos)/sizeof(best_pos[0])];
    uint32_t *offit = best_off + 2;
    for (const uint32_t *posit = best_pos + 2;
          posit < end_best_pos; ++posit, ++offit) {
      *offit = (*posit > 0) ? pos2off(s, *posit - 1) : 0;
    }
  }

  Dict_reset_next_input_entry(dict, s, &dict->match3, &dict->match2);

  Match2_add(&dict->match2, (uint16_t)(s->wind_b), dict->buffer);

  get_byte(s, dict->buffer);

  if (best_char < 0) {
    s->buf_sz = 0;
    *lb_len = 0;
    /* Signal exit */
  } else {
    s->buf_sz = s->wind_sz + 1;
  }
  s->bufp = s->inp - s->buf_sz;
}

static void find_better_match(const uint32_t best_off[MaxMatchByLengthLen], uint32_t* p_lb_len, uint32_t* p_lb_off) {
  if (*p_lb_len <= M2MinLen || *p_lb_off <= M2MaxOffset)
    return;
  if (*p_lb_off > M2MaxOffset && *p_lb_len >= M2MinLen + 1 && *p_lb_len <= M2MaxLen + 1 &&
      best_off[*p_lb_len - 1] != 0 && best_off[*p_lb_len - 1] <= M2MaxOffset) {
    *p_lb_len -= 1;
    *p_lb_off = best_off[*p_lb_len];
  } else if (*p_lb_off > M3MaxOffset && *p_lb_len >= M4MaxLen + 1 && *p_lb_len <= M2MaxLen + 2 &&
             best_off[*p_lb_len - 2] && best_off[*p_lb_len] <= M2MaxOffset) {
    *p_lb_len -= 2;
    *p_lb_off = best_off[*p_lb_len];
  } else if (*p_lb_off > M3MaxOffset && *p_lb_len >= M4MaxLen + 1 && *p_lb_len <= M3MaxLen + 1 &&
             best_off[*p_lb_len - 1] != 0 && best_off[*p_lb_len - 2] <= M3MaxOffset) {
    *p_lb_len -= 1;
    *p_lb_off = best_off[*p_lb_len];
  }
}

static lzokay_EResult encode_literal_run(uint8_t** outpp, const uint8_t* outp_end, const uint8_t* dst, size_t *dst_size,
                                  const uint8_t* lit_ptr, uint32_t lit_len) {
  uint8_t* outp = *outpp;
  if (outp == dst && lit_len <= 238) {
    NEEDS_OUT(1);
    *outp++ = (uint8_t)(17 + lit_len);
    *outpp = outp;
  } else if (lit_len <= 3) {
    outp[-2] = (uint8_t)(outp[-2] | lit_len);
  } else if (lit_len <= 18) {
    NEEDS_OUT(1);
    *outp++ = (uint8_t)(lit_len - 3);
    *outpp = outp;
  } else {
    NEEDS_OUT((lit_len - 18) / 255 + 2);
    *outp++ = 0;
    *outpp = outp;
    WRITE_ZERO_BYTE_LENGTH(lit_len - 18);
  }
  NEEDS_OUT(lit_len);
  memcpy(outp, lit_ptr, lit_len);
  outp += lit_len;
  *outpp = outp;
  return EResult_Success;
}

static lzokay_EResult encode_lookback_match(uint8_t* outp, const uint8_t* outp_end, const uint8_t* dst, size_t *dst_size,
                                     uint32_t lb_len, uint32_t lb_off, uint32_t last_lit_len) {
  if (lb_len == 2) {
    lb_off -= 1;
    NEEDS_OUT(2);
    *outp++ = (uint8_t)(M1Marker | ((lb_off & 0x3) << 2));
    *outp++ = (uint8_t)(lb_off >> 2);
  } else if (lb_len <= M2MaxLen && lb_off <= M2MaxOffset) {
    lb_off -= 1;
    NEEDS_OUT(2);
    *outp++ = (uint8_t)((lb_len - 1) << 5 | ((lb_off & 0x7) << 2));
    *outp++ = (uint8_t)(lb_off >> 3);
  } else if (lb_len == M2MinLen && lb_off <= M1MaxOffset + M2MaxOffset && last_lit_len >= 4) {
    lb_off -= 1 + M2MaxOffset;
    NEEDS_OUT(2);
    *outp++ = (uint8_t)(M1Marker | ((lb_off & 0x3) << 2));
    *outp++ = (uint8_t)(lb_off >> 2);
  } else if (lb_off <= M3MaxOffset) {
    lb_off -= 1;
    if (lb_len <= M3MaxLen) {
      NEEDS_OUT(1);
      *outp++ = (uint8_t)(M3Marker | (lb_len - 2));
    } else {
      lb_len -= M3MaxLen;
      NEEDS_OUT(lb_len / 255 + 2);
      *outp++ = (uint8_t)(M3Marker);
      WRITE_ZERO_BYTE_LENGTH(lb_len);
    }
    NEEDS_OUT(2);
    *outp++ = (uint8_t)(lb_off << 2);
    *outp++ = (uint8_t)(lb_off >> 6);
  } else {
    lb_off -= 0x4000;
    if (lb_len <= M4MaxLen) {
      NEEDS_OUT(1);
      *outp++ = (uint8_t)(M4Marker | ((lb_off & 0x4000) >> 11) | (lb_len - 2));
    } else {
      lb_len -= M4MaxLen;
      NEEDS_OUT(lb_len / 255 + 2);
      *outp++ = (uint8_t)(M4Marker | ((lb_off & 0x4000) >> 11));
      WRITE_ZERO_BYTE_LENGTH(lb_len);
    }
    NEEDS_OUT(2);
    *outp++ = (uint8_t)(lb_off << 2);
    *outp++ = (uint8_t)(lb_off >> 6);
  }
  return EResult_Success;
}

lzokay_EResult lzokay_compress_dict(const uint8_t* src, size_t src_size,
                 uint8_t* dst, size_t init_dst_size,
                 size_t *dst_size, struct lzokay_Dict* dict_storage) {
  lzokay_EResult err;
  struct State s;
  *dst_size = init_dst_size;
  uint8_t* outp = dst;
  uint8_t* outp_end = dst + init_dst_size;
  uint32_t lit_len = 0;
  uint32_t lb_off, lb_len;
  uint32_t best_off[MaxMatchByLengthLen];
  Dict_init(dict_storage, &s, src, src_size);
  const uint8_t* lit_ptr = s.inp;
  Dict_advance(dict_storage, &s, &lb_off, &lb_len, best_off, false);
  while (s.buf_sz > 0) {
    if (lit_len == 0)
      lit_ptr = s.bufp;
    if (lb_len < 2 || (lb_len == 2 && (lb_off > M1MaxOffset || lit_len == 0 || lit_len >= 4)) ||
        (lb_len == 2 && outp == dst) || (outp == dst && lit_len == 0)) {
      lb_len = 0;
    } else if (lb_len == M2MinLen && lb_off > M1MaxOffset + M2MaxOffset && lit_len >= 4) {
      lb_len = 0;
    }
    if (lb_len == 0) {
      ++lit_len;
      Dict_advance(dict_storage, &s, &lb_off, &lb_len, best_off, false);
      continue;
    }
    find_better_match(best_off, &lb_len, &lb_off);
    if ((err = encode_literal_run(&outp, outp_end, dst, dst_size, lit_ptr, lit_len)) < EResult_Success)
      return err;
    if ((err = encode_lookback_match(outp, outp_end, dst, dst_size, lb_len, lb_off, lit_len)) < EResult_Success)
      return err;
    lit_len = 0;
    Dict_advance(dict_storage, &s, &lb_off, &lb_len, best_off, true);
  }
  if ((err = encode_literal_run(&outp, outp_end, dst, dst_size, lit_ptr, lit_len)) < EResult_Success)
    return err;

  /* Terminating M4 */
  NEEDS_OUT(3);
  *outp++ = M4Marker | 1;
  *outp++ = 0;
  *outp++ = 0;

  *dst_size = outp - dst;
  return EResult_Success;
}
