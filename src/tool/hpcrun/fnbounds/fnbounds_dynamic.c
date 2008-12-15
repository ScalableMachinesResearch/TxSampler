//=====================================================================
// File: fnbounds_dynamic.c  
// 
//     provide information about function bounds for functions in
//     dynamically linked load modules. use an extra "server" process
//     to handle computing the symbols to insulate the client process
//     from the complexity of this task, including use of the system
//     command to fork new processes. having the server process
//     enables use to avoid dealing with forking off new processes
//     with system when there might be multiple threads active with
//     sampling enabled.
//
//  Modification history:
//     2008 April 28 - created John Mellor-Crummey
//
// $Id$
//=====================================================================


//*********************************************************************
// system includes
//*********************************************************************

#include <dlfcn.h>     // for dlopen/dlclose
#include <string.h>    // for strcmp, strerror
#include <stdlib.h>    // for getenv
#include <errno.h>     // for errno
#include <sys/mman.h>
#include <sys/param.h> // for PATH_MAX
#include <sys/stat.h>  // mkdir
#include <sys/types.h>
#include <unistd.h>    // getpid
#include <fcntl.h>


//*********************************************************************
// local includes
//*********************************************************************

#include "csprof_dlfns.h"
#include "dylib.h"
#include "epoch.h"
#include "fnbounds-file-header.h"
#include "fnbounds_interface.h"
#include "monitor.h"
#include "pmsg.h"
#include "structs.h"
#include "system_server.h"
#include "unlink.h"
#include "spinlock.h"
#include "thread_data.h"


//*********************************************************************
// local types
//*********************************************************************

typedef struct dso_info_s {
  char *name;
  void *start_addr;
  void *end_addr;
  void **table;
  long map_size;
  int  nsymbols;
  int  relocate;
  struct dso_info_s *next, *prev;
} dso_info_t;

#define PERFORM_RELOCATION(addr, base) \
	((void *) (((unsigned long) addr) + ((unsigned long) base)))

#define MAPPING_END(addr, length) \
	((void *) (((unsigned long) addr) + ((unsigned long) length)))


//*********************************************************************
// local variables
//*********************************************************************

// FIXME: tmproot should be overridable with an option.
static char *tmproot = "/tmp";

static char fnbounds_tmpdir[PATH_MAX];

static dso_info_t *dso_open_list;
static dso_info_t *dso_closed_list;

static dso_info_t *dso_free_list;

// locking functions to ensure that dynamic bounds data structures 
// are consistent.

static spinlock_t fnbounds_lock = SPINLOCK_UNLOCKED;

#define FNBOUNDS_LOCK  do {			\
	spinlock_lock(&fnbounds_lock);		\
	TD_GET(fnbounds_lock) = 1;		\
} while (0)

#define FNBOUNDS_UNLOCK  do {			\
	spinlock_unlock(&fnbounds_lock);	\
	TD_GET(fnbounds_lock) = 0;		\
} while (0)


//*********************************************************************
// forward declarations
//*********************************************************************

static void        fnbounds_tmpdir_remove();
static int         fnbounds_tmpdir_create();
static char *      fnbounds_tmpdir_get();

static dso_info_t *fnbounds_dso_info_get(void *pc);
static dso_info_t *fnbounds_compute(const char *filename,
				    void *start, void *end);
static dso_info_t *fnbounds_dso_info_query(void *pc, dso_info_t * dl_list);
static dso_info_t *fnbounds_dso_handle_open(const char *module_name,
					    void *start, void *end);
static void        fnbounds_map_executable();
static void        fnbounds_epoch_finalize_locked();

static dso_info_t *new_dso_info_t(const char *name, void **table,
				  struct fnbounds_file_header *fh,
				  void *startaddr, void *endaddr,
				  long map_size);

static const char *mybasename(const char *string);

static dso_info_t *dso_list_head(dso_info_t *dso_list);
static void        dso_list_add(dso_info_t **dso_list, dso_info_t *self);
static void        dso_list_remove(dso_info_t **dso_list, dso_info_t *self);

static dso_info_t *dso_info_allocate();
static void        dso_info_free(dso_info_t *unused);

static char *nm_command = 0;


//*********************************************************************
// interface operations
//*********************************************************************

//---------------------------------------------------------------------
// function fnbounds_init: 
// 
//     for dynamically-linked executables, start an fnbounds server
//     process to that will compute function bounds information upon
//     demand for dynamically-linked load modules.
//
//     return code = 0 upon success, otherwise fork failed 
//
//     NOTE: don't make this routine idempotent: it may be needed to
//     start a new server if the process forks
//---------------------------------------------------------------------

int 
fnbounds_init()
{
  int result = system_server_start();
  if (result == 0) {
    result = fnbounds_tmpdir_create();
    if (result == 0) {
      nm_command = getenv("CSPROF_NM_COMMAND"); 
  
      fnbounds_map_executable();
      fnbounds_map_open_dsos();
    } else {
      system_server_shutdown();
    }
  }
  return result;
}


int
fnbounds_enclosing_addr(void *pc, void **start, void **end)
{
  FNBOUNDS_LOCK;

  int ret = 1; // failure unless otherwise reset to 0 below

  dso_info_t *r = fnbounds_dso_info_get(pc);
  
  if (r && r->nsymbols > 0) { 
    void * relative_pc = pc;

    if (r->relocate) {
      relative_pc =  (void *) ((unsigned long) relative_pc) - 
	((unsigned long) r->start_addr); 
    }

    ret =  fnbounds_table_lookup(r->table, r->nsymbols, relative_pc, 
				 (void **) start, (void **) end);

    if (ret == 0 && r->relocate) {
      *start = PERFORM_RELOCATION(*start, r->start_addr);
      *end   = PERFORM_RELOCATION(*end  , r->start_addr);
    }
  }

  FNBOUNDS_UNLOCK;

  return ret;
}


//---------------------------------------------------------------------
// Function: fnbounds_map_open_dsos
// Purpose:  
//     identify any new dsos that have been mapped.
//     analyze them and add their information to the open list.
//---------------------------------------------------------------------

void
fnbounds_map_open_dsos()
{
  dylib_map_open_dsos();
}


//---------------------------------------------------------------------
// Function: fnbounds_unmap_closed_dsos
// Purpose:  
//     identify any dsos that are no longer mapped.
//     move them from the open to the closed list.
//---------------------------------------------------------------------

void
fnbounds_unmap_closed_dsos()
{
  FNBOUNDS_LOCK;

  dso_info_t *dso_info, *next;
  for (dso_info = dso_open_list; dso_info; dso_info = next) {
    next = dso_info->next;
    if (!dylib_addr_is_mapped((unsigned long long) dso_info->start_addr)) {
      
      // remove from open list of DSOs
      dso_list_remove(&dso_open_list, dso_info);

      // add to closed list of DSOs 
      dso_list_add(&dso_closed_list, dso_info);

      // Free the table memory.
      munmap(dso_info->table, dso_info->map_size);
    }
  }

  FNBOUNDS_UNLOCK;
}


int
fnbounds_note_module(const char *module_name, void *start, void *end)
{
  int success;

  //-------------------------------------------------------------------
  // check if the file is a dso containing fnbounds information that
  // we mapped by checking to see if the mapped file is in csprof's
  // temporary directory.
  //-------------------------------------------------------------------

  if (strncmp(fnbounds_tmpdir, module_name, strlen(fnbounds_tmpdir)) == 0) {
    success = 1; // it is one of ours, no processing needed. indicate success.
  } else {

    FNBOUNDS_LOCK;
    dso_info_t *tmp = fnbounds_dso_info_query(start, dso_open_list);

    if (tmp) {
      success = 1; // already mapped
    } else {
      dso_info_t *dso_info = fnbounds_dso_handle_open(module_name, start, end);
      success =  (dso_info ? 1 : 0); 
    } 
    FNBOUNDS_UNLOCK;
  }

  return success;
}


//---------------------------------------------------------------------
// function fnbounds_fini: 
// 
//     for dynamically-linked executables, shut down the fnbounds
//     server process
//---------------------------------------------------------------------

void 
fnbounds_fini()
{
  system_server_shutdown();
  fnbounds_tmpdir_remove();
}


void
fnbounds_epoch_finalize()
{
  FNBOUNDS_LOCK;
  fnbounds_epoch_finalize_locked();
  FNBOUNDS_UNLOCK;
}

void
fnbounds_release_lock(void)
{
  FNBOUNDS_UNLOCK;  
}


//*********************************************************************
// private operations
//
// Note: the private operations should all assume that fnbounds_lock
// is already locked (mostly).
//*********************************************************************

//
// Read the binary file of function addresses from hpcfnbounds-bin and
// load into memory as an array of void *.
//
// Returns: pointer to array on success and fills in map_size and file
//          header, else NULL on failure.
//
static void *
fnbounds_read_nm_file(const char *file, long *map_size,
		      struct fnbounds_file_header *fh)
{
  struct stat st;
  char *table;
  long pagesize, len, ret;
  int fd;

  if (file == NULL || map_size == NULL || fh == NULL) {
    EMSG("passed NULL to fnbounds_read_nm_file");
    return (NULL);
  }
  if (stat(file, &st) != 0) {
    EMSG("stat failed on fnbounds file: %s", file);
    return (NULL);
  }
  if (st.st_size < sizeof(*fh)) {
    EMSG("fnbounds file too small (%ld bytes): %s",
	 (long)st.st_size, file);
    return (NULL);
  }
  //
  // Round up map_size to multiple of page size and mmap().
  //
  pagesize = getpagesize();
  *map_size = (st.st_size/pagesize + 1)*pagesize;
  table = mmap(NULL, *map_size, PROT_READ | PROT_WRITE,
	       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (table == NULL) {
    EMSG("mmap failed on fnbounds file: %s", file);
    return (NULL);
  }
  //
  // Read the file into memory.  Note: we read() the file instead of
  // mmap()ing it directly, so we can close() it immediately.
  //
  fd = open(file, O_RDONLY);
  if (fd < 0) {
    EMSG("open failed on fnbounds file: %s", file);
    return (NULL);
  }
  len = 0;
  while (len < st.st_size) {
    ret = read(fd, table + len, st.st_size - len);
    if (ret <= 0) {
      EMSG("read failed on fnbounds file: %s", file);
      close (fd);
      return (NULL);
    }
    len += ret;
  }
  close(fd);

  memcpy(fh, table + st.st_size - sizeof(*fh), sizeof(*fh));
  if (fh->magic != FNBOUNDS_MAGIC) {
    EMSG("bad magic in fnbounds file: %s", file);
    return (NULL);
  }
  if (st.st_size < fh->num_entries * sizeof(void *)) {
    EMSG("fnbounds file too small (%ld bytes, %ld entries): %s",
	 (long)st.st_size, (long)fh->num_entries, file);
    return (NULL);
  }
  return (void *)table;
}


static dso_info_t *
fnbounds_compute(const char *incoming_filename, void *start, void *end)
{
  char filename[PATH_MAX];
  char command[MAXPATHLEN+1024];
  char dlname[MAXPATHLEN];
  int  logfile_fd = csprof_logfile_fd();

  if (nm_command == NULL || incoming_filename == NULL)
    return (NULL);

  realpath(incoming_filename, filename);
  sprintf(dlname, FNBOUNDS_BINARY_FORMAT, fnbounds_tmpdir_get(), mybasename(filename));

  sprintf(command, "%s -b %s %s %s 1>&%d 2>&%d\n",
	  nm_command, ENABLED(DL_BOUND_SCRIPT_DEBUG) ? "-t -v" : "",
	  filename, fnbounds_tmpdir_get(), logfile_fd, logfile_fd);
  TMSG(DL_BOUND, "system command = %s", command);

  int result = system_server_execute_command(command);
  if (result) {
    EMSG("fnbounds server command failed for file %s, aborting", filename);
    monitor_real_exit(1);
  }

  long map_size;
  struct fnbounds_file_header fh;
  void **nm_table = (void **)fnbounds_read_nm_file(dlname, &map_size, &fh);
  if (nm_table == NULL) {
    EMSG("fnbounds computed bogus symbols for file %s, aborting",filename);
    monitor_real_exit(1);
  }

  if (fh.num_entries < 1)
    return (NULL);

  //
  // Note: we no longer care if binary is stripped.
  //
  if (fh.relocatable) {
    if (nm_table[0] >= start && nm_table[0] <= end) {
      // segment loaded at its preferred address
      fh.relocatable = 0;
    }
  } else {
    char executable_name[PATH_MAX];
    unsigned long long mstart, mend;
    if (dylib_find_module_containing_addr((unsigned long long) nm_table[0],
					  executable_name, &mstart, &mend)) {
      start = (void *) mstart;
      end = (void *) mend;
    } else {
      start = nm_table[0];
      end = nm_table[fh.num_entries - 1];
    }
  }
  return new_dso_info_t(filename, nm_table, &fh, start, end, map_size);
}


static void
fnbounds_epoch_finalize_locked()
{
  dso_info_t *dso_info;

  for (dso_info = dso_open_list; dso_info; dso_info = dso_info->next) {
    csprof_epoch_add_module(dso_info->name, NULL /* no vaddr */,
			    dso_info->start_addr, 
			    dso_info->end_addr - dso_info->start_addr);
  } 

  dso_info_t *next;
  for (dso_info = dso_closed_list; dso_info;) {
    csprof_epoch_add_module(dso_info->name, NULL /* no vaddr */,
			    dso_info->start_addr, 
			    dso_info->end_addr - dso_info->start_addr);
    next = dso_info->next;
    dso_list_remove(&dso_closed_list, dso_info);
    dso_info_free(dso_info);
    dso_info = next;
  } 
}


static dso_info_t *
fnbounds_dso_info_query(void *pc, dso_info_t * dl_list)
{
  dso_info_t *dso_info = dl_list;

  //-------------------------------------------------------------------
  // see if we already have function bounds information computed for a
  // dso containing this pc
  //-------------------------------------------------------------------

  while (dso_info && (pc < dso_info->start_addr || pc > dso_info->end_addr)) 
    dso_info = dso_info->next; 

  return dso_info;
}


static dso_info_t *
fnbounds_dso_handle_open(const char *module_name, void *start, void *end)
{
  dso_info_t *dso_info = fnbounds_dso_info_query(start, dso_closed_list);

  // the address range of the module, which does not have an open mapping
  // was found to conflict with the address range of a module on the closed
  // list. 
  if (dso_info) {
    if (strcmp(module_name, dso_info->name) == 0 && 
        start == dso_info->start_addr && 
        end == dso_info->end_addr) {
      // reopening a closed module at the same spot in the address. 
      // move the record from the closed list to the open list, 
      // reopen the symbols, and we are done.

      // remove from closed list of DSOs
      dso_list_remove(&dso_closed_list, dso_info);

      // place dso_info on the free list. it will immediately be reclaimed by 
      // fnbounds_compute which will fill in the data and remap the fnbounds 
      // information into memory.
      dso_info_free(dso_info);

      // NOTE: if we refactored fnbounds_compute, we could avoid some of the 
      // costs since bounds information must already be computed on disk and 
      // only needs to be mapped. however, this doesn't seem worth the effort 
      // at present.
    } else {
      // the entry on the closed list was not the same module
      fnbounds_epoch_finalize_locked();
      csprof_epoch_new();
    }
  }
  dso_info = fnbounds_compute(module_name, start, end);

  return dso_info;
}


static dso_info_t *
fnbounds_dso_info_get(void *pc)
{
  dso_info_t *dso_open = fnbounds_dso_info_query(pc, dso_open_list);

  if (!dso_open) {

    //-----------------------------------------------------------------
    // we don't have any function bounds information for an open dso 
    // containing this pc.
    //-----------------------------------------------------------------

    if (csprof_dlopen_pending()) {

      //---------------------------------------------------------------
      // a new dso might have been just mapped without our knowledge.
      // see if we can locate the name and address range of a dso 
      // containing this pc.
      //---------------------------------------------------------------

      char module_name[PATH_MAX];
      unsigned long long addr, mstart, mend;
      addr = (unsigned long long) pc;
      
      if (dylib_find_module_containing_addr(addr, module_name, &mstart, &mend)) {
	dso_open = fnbounds_dso_handle_open(module_name, (void *) mstart, 
					    (void *) mend);
      }
    }
  }

  return dso_open;
}


static void
fnbounds_map_executable()
{
  dylib_map_executable();
}


static dso_info_t *
new_dso_info_t(const char *name, void **table, struct fnbounds_file_header *fh,
	       void *startaddr, void *endaddr, long map_size)
{
  int namelen = strlen(name) + 1;
  dso_info_t *r  = dso_info_allocate();
  
  TMSG(MALLOC," new_dso_info_t");
  r->name = (char *) csprof_malloc(namelen);
  strcpy(r->name, name);
  r->table = table;
  r->map_size = map_size;
  r->nsymbols = fh->num_entries;
  r->relocate = fh->relocatable;
  r->start_addr = startaddr;
  r->end_addr = endaddr;

  dso_list_add(&dso_open_list, r);

  return r;
}


static const char *
mybasename(const char *string)
{
  char *suffix = rindex(string, '/');
  if (suffix) return suffix + 1;
  else return string;
}


//*********************************************************************
// temporary directory
//*********************************************************************

static int 
fnbounds_tmpdir_create()
{
  int i, result;
  // try multiple times to create a temporary directory 
  // with the aim of avoiding failure
  for (i = 0; i < 10; i++) {
    sprintf(fnbounds_tmpdir,"%s/%d-%d", tmproot, (int) getpid(),i);
    result = mkdir(fnbounds_tmpdir, 0777);
    if (result == 0) break;
  }
  if (result)  {
    char buffer[1024];
    EMSG("fatal error: unable to make temporary directory %s (error = %s)\n", 
          fnbounds_tmpdir, strerror_r(errno, buffer, 1024));
  } 
  return result;
}


static char *
fnbounds_tmpdir_get()
{
  return fnbounds_tmpdir;
}


static void 
fnbounds_tmpdir_remove()
{
  IF_NOT_DISABLED(DL_BOUND_UNLINK){
    unlink_tree(fnbounds_tmpdir);
  }
}


//*********************************************************************
// list operations
//*********************************************************************

static dso_info_t * 
dso_list_head(dso_info_t *dso_list)
{
  return dso_list;
}

static void 
dso_list_add(dso_info_t **dso_list, dso_info_t *self)
{
  // add self at head of list
  self->next = *dso_list;
  self->prev = NULL;
  *dso_list = self;
}

static void 
dso_list_remove(dso_info_t **dso_list, dso_info_t *self)
{
  dso_info_t *prev = self->prev;

  if (prev) {
    // have a predecessor: not at head of list 
    // 1. adjust predecessor to point to my successor 
    // 2. forget about my predecessor 
    prev->next = self->next;
    self->prev = NULL;
  } else {
    // no predecessor: at head of list
    // repoint list head to next 
    *dso_list = self->next;
  }

  // forget about my successor 
  self->next = 0;
}


//*********************************************************************
// allocation/deallocation of dso_info_t records
//*********************************************************************

static dso_info_t *
dso_info_allocate()
{
  static dso_info_t *dso_free_list = 0;
  dso_info_t *new = dso_list_head(dso_free_list);
  if (new) {
    dso_list_remove(&dso_free_list, new);
  } else {
    TMSG(MALLOC," dso_info_allocate");
    new = (dso_info_t *) csprof_malloc(sizeof(dso_info_t));
  }
  return new;
}


static void
dso_info_free(dso_info_t *unused)
{
  dso_list_add(&dso_free_list, unused);
}


//*********************************************************************
// debugging support
//*********************************************************************

void 
dump_dso_info_t(dso_info_t *r)
{
  printf("%p-%p %s [dso_info_t *%p, table=%p, nsymbols=%d, relocatable=%d]\n",
	 r->start_addr, r->end_addr, r->name, 
         r, r->table, r->nsymbols, r->relocate);
#if 0
  printf("record addr = %p: name = '%s', table = %p, nsymbols = 0x%x, "
	 "start = %p, end = %p, relocate = %d\n",
         r, r->name, r->table, r->nsymbols, r->start_addr, 
	 r->end_addr, r->relocate);
#endif
}


void 
dump_dso_list(dso_info_t *dl_list)
{
  dso_info_t *r = dl_list;
  for (; r; r = r->next) dump_dso_info_t(r);
}