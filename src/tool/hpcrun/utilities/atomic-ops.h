#ifndef atomic_ops_h
#define atomic_ops_h

#include "atomic-op-bodies.h"

#if defined(LL_BODY)

inline static unsigned long load_linked(volatile unsigned long *ptr)
{
   volatile unsigned long result;
   LL_BODY;
   return result;
}

#endif

#if defined(SC_BODY) 

/* if successful, return 1 */
inline static int store_conditional(volatile unsigned long *ptr, unsigned long val)
{
   int result;
   SC_BODY;
   return result;
}

#endif

#if defined (LL_BODY) && defined(SC_BODY) && !defined(CAS_BODY)

#define CAS_BODY                                                                    \
  for(;;) {                                                                         \
    prev = load_linked(ptr);                                                        \
    if (prev != old || store_conditional(ptr, new)) break;                          \
  }

#endif

#if defined(CAS_BODY) 

static inline unsigned long
compare_and_swap(volatile void *ptr, unsigned long old, unsigned long new)
{
  unsigned long prev;
  CAS_BODY;
  return prev;
}

#endif


#if defined (LL_BODY) && defined(SC_BODY) 

#define read_modify_write(type, addr, expn, result) {                              \
    type __new;                                                                    \
    do {                                                                           \
      result = (type) load_linked((unsigned long *) addr);                         \
      __new = expn;                                                                \
    } while (!store_conditional((unsigned long *) addr, (unsigned long) __new));   \
}

#else

#define read_modify_write(type, addr, expn, result) {                              \
    type __new;                                                                    \
    do {                                                                           \
      result = *addr;                                                              \
      __new = expn;                                                                \
    } while (compare_and_swap(addr, result, __new) != result);                     \
}

#endif

static inline long
fetch_and_add(volatile long *addr, long val)
{
    long result;
    read_modify_write(long, addr, result + val, result);
    return result;
}


static inline long
fetch_and_store(volatile long *addr, long new)
{
    long result;
    read_modify_write(long, addr, new, result);
    return result;
}

#define fetch_and_store_ptr(vaddr, ptr) ((void *) fetch_and_store((volatile long *)vaddr, (long) ptr))


#endif // atomic_ops_h