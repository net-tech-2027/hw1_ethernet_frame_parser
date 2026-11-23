#include "ethernet.h"

#include <string.h>
int eth_frame_parse(const uint8_t *buf, size_t len, eth_frame_t *out) {
  (void)buf;
  (void)len;
  (void)out;
  return -1;
}

int eth_frame_serialize(const eth_frame_t *frame, uint8_t *out,
                        size_t out_size) {
  (void)frame;
  (void)out;
  (void)out_size;
  return -1;
}
