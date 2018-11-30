#include "shadow-memory.h"

#include <string.h>
#include <sys/mman.h>

#include "memory/hpcrun-malloc.h"

/* MACROs */
// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(void *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) (((addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) (((addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)

#define SHADOWDATATYPE_BYTE unsigned long
#define SHADOWDATATYPE_CACHELINE uint64_t

#define CACHELINE(addr) (addr >> 6) //64 bytes per cache line

#define GET_WRITE_BIT(shadow_data) (shadow_data >> 63) //the most significant bit is the write bit
#define GET_TID(shadow_data) (shadow_data & ((1UL << 63) - 1))

#define COMPOSE_SHADOW_DATA(tid, isWrite) ( tid | ((uint64_t)isWrite << 63))

uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];
uint8_t ** gL1CachePageTable[LEVEL_1_PAGE_TABLE_SIZE];

/* helper functions for shadow memory */
static uint8_t* get_shadow_base_address_from_byte_table(uint64_t address) {
  uint8_t *shadowPage;
  uint8_t ***l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
  if(*l1Ptr == 0) {
    *l1Ptr = (uint8_t **) hpcrun_malloc(LEVEL_2_PAGE_TABLE_SIZE);
    memset(*l1Ptr, 0, LEVEL_2_PAGE_TABLE_SIZE);
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * sizeof(SHADOWDATATYPE_BYTE), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * sizeof(SHADOWDATATYPE_BYTE), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  return shadowPage;
}

static uint8_t* get_shadow_base_address_from_cacheline_table(uint64_t address) {
  uint8_t *shadowPage;
  uint8_t ***l1Ptr = &gL1CachePageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
  if(*l1Ptr == 0) {
    *l1Ptr = (uint8_t **) hpcrun_malloc(LEVEL_2_PAGE_TABLE_SIZE);
    memset(*l1Ptr, 0, LEVEL_2_PAGE_TABLE_SIZE);
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * sizeof(SHADOWDATATYPE_CACHELINE), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
    shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * sizeof(SHADOWDATATYPE_CACHELINE), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  }
  return shadowPage;
}


/* get the stored data from the shadow memory and store the new one */
static SHADOWDATATYPE_BYTE get_and_store_in_byte_table(uint64_t addr, unsigned long tid, unsigned short store_flag){
  uint8_t* status = get_shadow_base_address_from_byte_table(addr);
  SHADOWDATATYPE_BYTE *prevAddr = (SHADOWDATATYPE_BYTE *)(status + PAGE_OFFSET(addr) * sizeof(SHADOWDATATYPE_BYTE));
  SHADOWDATATYPE_BYTE ret_value = *prevAddr;
  if (store_flag != 0){
    *prevAddr = (SHADOWDATATYPE_BYTE) tid;
  }
  return ret_value;
}

static SHADOWDATATYPE_CACHELINE get_and_store_in_cacheline_table(uint64_t addr, unsigned long tid, unsigned short store_flag){
    uint8_t* status = get_shadow_base_address_from_cacheline_table(CACHELINE(addr));
    SHADOWDATATYPE_CACHELINE *prevAddr = (SHADOWDATATYPE_CACHELINE *)(status + PAGE_OFFSET(CACHELINE(addr)) * sizeof(SHADOWDATATYPE_CACHELINE));
    SHADOWDATATYPE_CACHELINE ret_value = *prevAddr;
    if (store_flag != 0){
      *prevAddr = (SHADOWDATATYPE_CACHELINE) tid;
    }
    return ret_value;
}

int htm_record_and_get_contention(uint64_t addr, unsigned long tid, int is_write){
  //add into cache line map
  unsigned long cacheline_ret = get_and_store_in_cacheline_table(addr, COMPOSE_SHADOW_DATA(tid, is_write), 1);
  //add into byte map
  unsigned long byte_ret = get_and_store_in_byte_table(addr, COMPOSE_SHADOW_DATA(tid, is_write), 1);

  //False sharing: 1. another thread has touched the cache line; 2. the touched byte is NOT accessed by another thread
  if (cacheline_ret == 0) { //the cache line first-time touched
    return 0;
  }
  if (GET_WRITE_BIT(cacheline_ret) == 0 && is_write == 0){ //both READ, no false sharing
    return 0;
  }
  if ((GET_TID(cacheline_ret) != tid) && (byte_ret == 0 || GET_TID(byte_ret) == tid)) {
    return 1;
  }
  return 0;
}

