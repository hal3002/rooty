#include "rooty.h"

uint32_t decrypt_message(const uint8_t *data, uint8_t *decoded_data, uint32_t len, uint8_t *key) {
   uint32_t i;

   for(i = 0; i < len; i++) {
      decoded_data[i] = ((data[i] ^ key[0]) ^ key[1]);
   }

   return i;
}
