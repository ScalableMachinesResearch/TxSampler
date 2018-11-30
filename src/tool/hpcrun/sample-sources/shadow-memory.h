#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#include<stdint.h>

int htm_record_and_get_contention(uint64_t addr, unsigned long tid, int is_write);

#endif /* SHADOW_MEMORY_H */
