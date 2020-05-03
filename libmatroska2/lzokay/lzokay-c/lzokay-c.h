#ifndef LZOKAY_C_INCLUDED
#define LZOKAY_C_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define LZOKAY_SUCCESS    0
#define LZOKAY_ERROR     -1

int lzokay_decompress(const uint8_t * src, size_t src_size, uint8_t *output, size_t *output_len);

#ifdef __cplusplus
}
#endif

#endif // LZOKAY_C_INCLUDED
