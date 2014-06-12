#ifndef LIBALLOCS_PRIVATE_H_
#define LIBALLOCS_PRIVATE_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64)
#error Unsupported architecture.
#endif

#include "memtable.h"
#include "heap_index.h"
#include "allocsmt.h"
#include <stdint.h>

#include "liballocs.h"

extern uintptr_t page_size __attribute__((visibility("hidden")));
extern uintptr_t log_page_size __attribute__((visibility("hidden")));
extern uintptr_t page_mask __attribute__((visibility("hidden")));
#define ROUND_DOWN_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == 4096), ((n)>>12)<<12)
#define ROUND_UP_TO_PAGE_SIZE(n) \
	(assert(sysconf(_SC_PAGE_SIZE) == 4096), (n) % 4096 == 0 ? (n) : ((((n) >> 12) + 1) << 12))
// mappings over 4GB in size are assumed to be memtables and are ignored
#define BIGGEST_MAPPING (1ull<<32) 

const char *
dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
		__attribute__((visibility("hidden")));
char execfile_name[4096] __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
/* We use this prefix tree to map the address space. */
enum node_info_kind { DATA_PTR, INS_AND_BITS };
struct node_info
{
	enum node_info_kind what;
	union
	{
		const void *data_ptr;
		struct 
		{
			struct insert ins;
			unsigned is_object_start:1;
			unsigned npages:20;
			unsigned obj_offset:7;
		} ins_and_bits;
	} un;
};
typedef uint16_t mapping_num_t;
mapping_num_t *l0index __attribute__((visibility("hidden")));
extern _Bool initialized_maps __attribute__((visibility("hidden")));
struct prefix_tree_node {
	unsigned kind:4; // UNKNOWN, STACK, HEAP, STATIC
	struct node_info info;
};
struct prefix_tree_node *prefix_tree_add(void *base, size_t s, unsigned kind, const void *arg) __attribute__((visibility("hidden")));
void prefix_tree_add_sloppy(void *base, size_t s, unsigned kind, const void *arg) __attribute__((visibility("hidden")));
struct prefix_tree_node *prefix_tree_add_full(void *base, size_t s, unsigned kind, struct node_info *arg) __attribute__((visibility("hidden")));
void prefix_tree_del(void *base, size_t s) __attribute__((visibility("hidden")));
void prefix_tree_del_node(struct prefix_tree_node *n) __attribute__((visibility("hidden")));
int prefix_tree_node_exact_match(struct prefix_tree_node *n, void *begin, void *end) __attribute__((visibility("hidden")));
size_t
prefix_tree_get_overlapping_mappings(struct prefix_tree_node **out_begin, 
		size_t out_size, void *begin, void *end) __attribute__((visibility("hidden")));
void init_prefix_tree_from_maps(void) __attribute__((visibility("hidden")));
void prefix_tree_add_missing_maps(void) __attribute__((visibility("hidden")));
enum object_memory_kind prefix_tree_get_memory_kind(const void *obj) __attribute__((visibility("hidden")));
void prefix_tree_print_all_to_stderr(void) __attribute__((visibility("hidden")));
struct prefix_tree_node *
prefix_tree_deepest_match_from_root(void *base, struct prefix_tree_node ***out_prev_ptr) __attribute__((visibility("hidden")));
struct prefix_tree_node *
prefix_tree_bounds(const void *ptr, const void **begin, const void **end) __attribute__((visibility("hidden")));
int __liballocs_add_all_mappings_cb(struct dl_phdr_info *info, size_t size, void *data) __attribute__((visibility("hidden")));
#define debug_printf(lvl, ...) do { \
    if ((lvl) <= __liballocs_debug_level) { \
      warnx( __VA_ARGS__ );  \
    } \
  } while (0)
#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
#else
extern void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
#endif

// extern inline struct uniqtype *allocsite_to_uniqtype(const void *allocsite) __attribute__((visibility("hidden")));
// extern inline struct uniqtype *allocsite_to_uniqtype(const void *allocsite)
// {
// 	assert(__liballocs_allocsmt != NULL);
// 	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, allocsite);
// 	struct allocsite_entry *bucket = *bucketpos;
// 	for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
// 	{
// 		if (p->allocsite == allocsite)
// 		{
// 			return p->uniqtype;
// 		}
// 	}
// 	return NULL;
// }
// 
// #define maximum_vaddr_range_size (4*1024) // HACK
// extern inline struct uniqtype *vaddr_to_uniqtype(const void *vaddr) __attribute__((visibility("hidden")));
// extern inline struct uniqtype *vaddr_to_uniqtype(const void *vaddr)
// {
// 	assert(__liballocs_allocsmt != NULL);
// 	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)vaddr | STACK_BEGIN));
// 	struct allocsite_entry **bucketpos = initial_bucketpos;
// 	_Bool might_start_in_lower_bucket = 1;
// 	do 
// 	{
// 		struct allocsite_entry *bucket = *bucketpos;
// 		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
// 		{
// 			/* NOTE that in this memtable, buckets are sorted by address, so 
// 			 * we would ideally walk backwards. We can't, so we peek ahead at
// 			 * p->next. */
// 			if (p->allocsite <= vaddr && 
// 				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > vaddr))
// 			{
// 				return p->uniqtype;
// 			}
// 			might_start_in_lower_bucket &= (p->allocsite > vaddr);
// 		}
// 		/* No match? then try the next lower bucket *unless* we've seen 
// 		 * an object in *this* bucket which starts *before* our target address. 
// 		 * In that case, no lower-bucket object can span far enough to reach our
// 		 * static_addr, because to do so would overlap the earlier-starting object. */
// 		--bucketpos;
// 	} while (might_start_in_lower_bucket && 
// 	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_vaddr_range_size);
// 	return NULL;
// }
// #undef maximum_vaddr_range_size
// 
// #define maximum_static_obj_size (256*1024) // HACK
// extern inline struct uniqtype *static_addr_to_uniqtype(const void *static_addr, void **out_object_start) __attribute__((visibility("hidden")));
// extern inline struct uniqtype *static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
// {
// 	assert(__liballocs_allocsmt != NULL);
// 	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (STACK_BEGIN<<1)));
// 	struct allocsite_entry **bucketpos = initial_bucketpos;
// 	_Bool might_start_in_lower_bucket = 1;
// 	do 
// 	{
// 		struct allocsite_entry *bucket = *bucketpos;
// 		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
// 		{
// 			/* NOTE that in this memtable, buckets are sorted by address, so 
// 			 * we would ideally walk backwards. We can't, so we peek ahead at
// 			 * p->next. */
// 			if (p->allocsite <= static_addr && 
// 				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > static_addr)) 
// 			{
// 				if (out_object_start) *out_object_start = p->allocsite;
// 				return p->uniqtype;
// 			}
// 			might_start_in_lower_bucket &= (p->allocsite > static_addr);
// 		}
// 		/* No match? then try the next lower bucket *unless* we've seen 
// 		 * an object in *this* bucket which starts *before* our target address. 
// 		 * In that case, no lower-bucket object can span far enough to reach our
// 		 * static_addr, because to do so would overlap the earlier-starting object. */
// 		--bucketpos;
// 	} while (might_start_in_lower_bucket && 
// 	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
// 	return NULL;
// }
// #undef maximum_vaddr_range_size

/* avoid dependency on libc headers (in this header only) */
void __assert_fail(const char *assertion, 
	const char *file, unsigned int line, const char *function);
void warnx(const char *fmt, ...);
unsigned long malloc_usable_size (void *ptr);

/* counters */
extern unsigned long __liballocs_aborted_stack __attribute__((visibility("protected")));
extern unsigned long __liballocs_aborted_static __attribute__((visibility("protected")));
extern unsigned long __liballocs_aborted_unknown_storage __attribute__((visibility("protected")));
extern unsigned long __liballocs_hit_heap_case __attribute__((visibility("protected")));
extern unsigned long __liballocs_hit_stack_case __attribute__((visibility("protected")));
extern unsigned long __liballocs_hit_static_case __attribute__((visibility("protected")));
extern unsigned long __liballocs_aborted_unindexed_heap __attribute__((visibility("protected")));
extern unsigned long __liballocs_aborted_unrecognised_allocsite __attribute__((visibility("protected")));

#endif
