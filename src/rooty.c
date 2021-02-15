#include "rooty.h"

uint32_t decrypt_message(ROOTY_MESSAGE *msg, uint32_t len) {
    uint32_t i, j;

    for(i=0, j=0; i < len - BLOCK_SIZE; i++) {
        msg->magic[i] = (msg->magic[i] ^ msg->key[j]);

        if ((j > 0) && (j % (BLOCK_SIZE - 1) == 0)) {
            j = 0; 
        } else { 
            j++; 
        }
   }

   return i;
}
