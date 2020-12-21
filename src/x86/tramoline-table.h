/* -----------------------------------------------------------------------
   tramoline-table.h

   x86 tramoline table implementation.

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   ``Software''), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
   ----------------------------------------------------------------------- */


/* How to make a trampoline table.  */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>

typedef struct ffi_trampoline_table ffi_trampoline_table;
typedef struct ffi_trampoline_table_entry ffi_trampoline_table_entry;

struct ffi_trampoline_table {
  /* contiguous writable and executable pages */
  void *config_page;
  void *trampoline_page;

  /* free list tracking */
  uint16_t free_count;
  ffi_trampoline_table_entry *free_list;
  ffi_trampoline_table_entry *free_list_pool;

  ffi_trampoline_table *prev;
  ffi_trampoline_table *next;
};

struct ffi_trampoline_table_entry {
  void *(*trampoline)();
  ffi_trampoline_table_entry *next;
};

/* Override the standard architecture trampoline size */
#undef FFI_TRAMPOLINE_SIZE
#define FFI_TRAMPOLINE_SIZE FFI_EXEC_TRAMPOLINE_TABLE_TRAMPOLINE_SIZE

#undef PAGE_SIZE
#define PAGE_SIZE FFI_EXEC_TRAMPOLINE_TABLE_PAGE_SIZE

/* The trampoline configuration is placed at 4096 bytes prior to the
   trampoline's entry point */
#define FFI_TRAMPOLINE_CODELOC_CONFIG(codeloc) \
  ((void **) (((uint8_t *) codeloc) - 4096));

/* Total number of trampolines that fit in one trampoline table */
#define FFI_TRAMPOLINE_COUNT (PAGE_SIZE / FFI_TRAMPOLINE_SIZE)

static pthread_mutex_t ffi_trampoline_lock = PTHREAD_MUTEX_INITIALIZER;
static ffi_trampoline_table *ffi_trampoline_tables = NULL;

static ffi_trampoline_table *
ffi_trampoline_table_alloc (void)
{
  ffi_trampoline_table *table = NULL;
  /* Trampoline to load the context argument from the config page.  */
  static const unsigned char trampoline[FFI_TRAMPOLINE_SIZE] = {
#ifdef __x86_64__
    /* endbr64 */
    0xf3, 0x0f, 0x1e, 0xfa,
    /* movq -4107(%rip),%r10 */
    0x4c, 0x8b, 0x15, 0xf5, 0xef, 0xff, 0xff,
    /* jmpq *-4105(%rip)  */
    0xff, 0x25, 0xf7, 0xef, 0xff, 0xff
#else
    /* endbr32 */
    0xf3, 0x0f, 0x1e, 0xfb,
    /* call 0 */
    0xe8, 0x00, 0x00, 0x00, 0x00,
    /* pop %edx */
    0x5a,
    /* sub $4105,%edx */
    0x81, 0xea, 0x09, 0x10, 0x00, 0x00,
    /* mov (%edx),%eax */
    0x8b, 0x02,
    /* jmp *0x4(%edx) */
    0xff, 0x62, 0x04
#endif
  };

  /* Loop until we can allocate two contiguous pages */
  while (table == NULL) {
    void *config_page;

    /* Try to allocate two pages */
    config_page = mmap (NULL, PAGE_SIZE*2, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (config_page == MAP_FAILED) {
      fprintf(stderr, "mmap() failure: %m at %s:%d\n",
	      __FILE__, __LINE__);
      break;
    }

    /* Create the trampoline table.  */
    void *trampoline_page = config_page+PAGE_SIZE;
    void *ptr = trampoline_page;
    unsigned int n = PAGE_SIZE / sizeof (trampoline);
    while (n-- > 0)
      ptr = mempcpy (ptr, trampoline, sizeof (trampoline));

    /* Update protection on the trampoline table */
    if (mprotect (trampoline_page, PAGE_SIZE,
		  PROT_READ | PROT_EXEC) != 0) {
      fprintf(stderr, "mprotect() failure: %m at %s:%d\n",
	      __FILE__, __LINE__);

      /* If we failed to update the trampoline page, drop our config
	 allocation mapping and retry */
      munmap (config_page, PAGE_SIZE * 2);
      continue;
    }

    /* We have valid trampoline and config pages */
    table = calloc (1, sizeof(ffi_trampoline_table));
    table->free_count = FFI_TRAMPOLINE_COUNT;
    table->config_page = config_page;
    table->trampoline_page = trampoline_page;

    /* Create and initialize the free list */
    table->free_list_pool = calloc(FFI_TRAMPOLINE_COUNT,
				   sizeof(ffi_trampoline_table_entry));

    uint16_t i;
    for (i = 0; i < table->free_count; i++) {
      ffi_trampoline_table_entry *entry = &table->free_list_pool[i];
      entry->trampoline = (void *) (table->trampoline_page
				    + (i * FFI_TRAMPOLINE_SIZE));

      if (i < table->free_count - 1)
	entry->next = &table->free_list_pool[i+1];
    }

    table->free_list = table->free_list_pool;
  }

  return table;
}

void *
ffi_closure_alloc (size_t size, void **code)
{
  /* Create the closure */
  ffi_closure *closure = malloc(size);
  if (closure == NULL)
    return NULL;

  pthread_mutex_lock(&ffi_trampoline_lock);

  /* Check for an active trampoline table with available entries. */
  ffi_trampoline_table *table = ffi_trampoline_tables;
  if (table == NULL || table->free_list == NULL) {
    table = ffi_trampoline_table_alloc ();
    if (table == NULL) {
      free(closure);
      return NULL;
    }

    /* Insert the new table at the top of the list */
    table->next = ffi_trampoline_tables;
    if (table->next != NULL)
      table->next->prev = table;

    ffi_trampoline_tables = table;
  }

  /* Claim the free entry */
  ffi_trampoline_table_entry *entry = ffi_trampoline_tables->free_list;
  ffi_trampoline_tables->free_list = entry->next;
  ffi_trampoline_tables->free_count--;
  entry->next = NULL;

  pthread_mutex_unlock(&ffi_trampoline_lock);

  /* Initialize the return values */
  *code = entry->trampoline;
  closure->trampoline_table = table;
  closure->trampoline_table_entry = entry;

  return closure;
}

void
ffi_closure_free (void *ptr)
{
  ffi_closure *closure = ptr;

  pthread_mutex_lock(&ffi_trampoline_lock);

  /* Fetch the table and entry references */
  ffi_trampoline_table *table = closure->trampoline_table;
  ffi_trampoline_table_entry *entry = closure->trampoline_table_entry;

  /* Return the entry to the free list */
  entry->next = table->free_list;
  table->free_list = entry;
  table->free_count++;

  /* If all trampolines within this table are free, and at least one
     other table exists, deallocate the table */
  if (table->free_count == FFI_TRAMPOLINE_COUNT
      && ffi_trampoline_tables != table) {
    /* Remove from the list */
    if (table->prev != NULL)
      table->prev->next = table->next;

    if (table->next != NULL)
      table->next->prev = table->prev;

    /* Deallocate pages */
    if (munmap (table->config_page, PAGE_SIZE) != 0)
      fprintf(stderr, "munmap() failure: %m at %s:%d\n",
	      __FILE__, __LINE__);

    if (munmap (table->trampoline_page, PAGE_SIZE) != 0)
      fprintf(stderr, "munmap() failure: %m at %s:%d\n",
	      __FILE__, __LINE__);

    /* Deallocate free list */
    free (table->free_list_pool);
    free (table);
  } else if (ffi_trampoline_tables != table) {
    /* Otherwise, bump this table to the top of the list */
    table->prev = NULL;
    table->next = ffi_trampoline_tables;
    if (ffi_trampoline_tables != NULL)
      ffi_trampoline_tables->prev = table;

    ffi_trampoline_tables = table;
  }

  pthread_mutex_unlock (&ffi_trampoline_lock);

  /* Free the closure */
  free (closure);
}
