#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include "relf.h" /* for fake_dlsym, used by callee wrappers */
#include "../include/liballocs_config.h"

#ifndef NO_TLS
extern __thread void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
extern __thread size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
extern __thread void *__current_freefn __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
extern __thread int __currently_allocating __attribute__((weak)); // defined by heap_index_hooks
#else // DOUBLE HACK: make weak *definitions* here
void *__current_allocsite __attribute__((weak)); // defined by heap_index_hooks
void *__current_allocfn __attribute__((weak)); // defined by heap_index_hooks
size_t __current_allocsz __attribute__((weak)); // defined by heap_index_hooks
void *__current_freefn __attribute__((weak)); // defined by heap_index_hooks
int __currently_freeing __attribute__((weak)); // defined by heap_index_hooks
int __currently_allocating __attribute__((weak)); // defined by heap_index_hooks
#endif

int  __index_small_alloc(void *ptr, int level, unsigned size_bytes); // defined by heap_index_hooks
void __unindex_small_alloc(void *ptr, int level); // defined by heap_index_hooks

#ifdef LIFETIME_POLICIES
int __generic_heap_check_for_free_cancellation(void *obj, void *freefn);
#else
#define __generic_heap_check_for_free_cancellation(obj, freefn) 0
#endif
#ifdef FINALIZER_LIST
void __generic_heap_set_deallocator(void *obj, void *freefn);
#endif

/* these are our per-allocfn caller wrappers */

#define make_argname(num, typ) \
	arg ## num

#define make_argtype(num, typ) \
	typ

#define make_argdecl(num, typ) \
	make_argtype(num, typ) make_argname(num, typ)

#define make_alloc_caller_wrapper(name) \
	void *__real_ ## name ( arglist_ ## name (make_argdecl) ); \
	void free_fn_ ## name (void *); \
	void *__wrap_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		void *retval; \
		if (&__current_allocfn && !__current_allocfn) \
		{ \
			_Bool set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			__current_freefn = &free_fn_ ## name; \
			retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
			__current_freefn = (void*)0; \
			if (set_currently_allocating) __currently_allocating = 0; \
		} \
		else \
		{ \
			/* printf("&__current_allocfn: %p    ", &__current_allocfn); */ \
			/* if (&__current_allocfn) printf("__current_allocfn: %d", __current_allocfn); */ \
			retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		} \
		return retval; \
	}

/* Unsized allocators should call a sized allocator during their execution.
 * Therefore we only set the deallocator here. (not using __current_freefn,
 * because only the returned value should have a custom deallocator) */
#ifdef FINALIZER_LIST
#define make_unsized_alloc_caller_wrapper(name) \
	void *__real_ ## name ( arglist_ ## name (make_argdecl) ); \
	void free_fn_ ## name (void *); \
	void *__wrap_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		void *retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		__generic_heap_set_deallocator(retval, free_fn_ ## name); \
		return retval; \
	}
#else
#define make_unsized_alloc_caller_wrapper(name)
#endif

/* For "size-only" caller wrappers, we leave the size *set* on return. 
 * "Action-only" and "normal" wrappers are the same case: 
 * FIXME: (Guillaume) I don't know why this is needed, so it may need some
 * adjustment. */
#define make_size_caller_wrapper(name) \
	void *__real_ ## name( arglist_ ## name (make_argdecl) ); \
	void *__wrap_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		void *retval; \
		if (&__current_allocsite && !__current_allocsite) \
		{ \
			_Bool set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			__current_allocsite = __builtin_return_address(0); \
			retval = __real_ ## name( arglist_ ## name (make_argname) ); \
			/* __current_alloclevel = 0; */ \
			if (set_currently_allocating) __currently_allocating = 0; \
			/* *leave* the site to be picked up the the next alloc action, in case we're a helper */ \
		} \
		else { \
			retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		} \
		return retval; \
	}
	
/* This is like the normal alloc caller wrapper but we allow for the fact that 
 * we're a nested allocator. FIXME: split off the callee stuff. */
#define make_suballocator_alloc_caller_wrapper(name) \
	static int name ## _alloclevel; /* FIXME: thread-safety for access to this. */\
	void *__real_ ## name ( arglist_ ## name (make_argdecl) ); \
	void *__wrap_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		_Bool have_caller_allocfn; \
		_Bool set_currently_allocating = 0; \
		if (&__current_allocfn && !__current_allocfn) /* This means we're not in any kind of alloc function yet */ \
		{ \
			set_currently_allocating = 0; \
			if (&__currently_allocating && !__currently_allocating) { \
				__currently_allocating = 1; \
				set_currently_allocating = 1; \
			} \
			/* only set the site if we don't have one already */ \
			if (!__current_allocsite) __current_allocsite = __builtin_return_address(0); \
			__current_allocfn = &__real_ ## name; \
			__current_allocsz = size_arg_ ## name; \
			have_caller_allocfn = 0; \
		}  else have_caller_allocfn = 1; \
		/* __current_alloclevel = 1; */ /* We're at least at level 1, i.e. below sbrk()/mmap(). pre_alloc increments this too */ \
		void *real_retval = __real_ ## name( arglist_ ## name (make_argname) ); \
		if (/* __current_alloclevel > name ## _alloclevel*/ 0) \
		{ \
			/* Warn if we've already initialized our_alloclevel and saw a greater level */ \
			if (name ## _alloclevel != 0) \
			{ \
				warnx("Warning: __wrap_%s operating at alloclevel %d greater than previous level %d", \
					#name, name ## _alloclevel, /* __current_alloclevel */ 0); \
			} \
			name ## _alloclevel = 0/*__current_alloclevel*/; \
		} \
		if (&__index_small_alloc) \
		{ \
			int seen_alloclevel = __index_small_alloc(real_retval, /* name ## _alloclevel */ -1, __current_allocsz); \
			assert(name ## _alloclevel == 0 || seen_alloclevel == name ## _alloclevel); \
			if (name ## _alloclevel == 0) name ## _alloclevel = seen_alloclevel; \
		} \
		if (!have_caller_allocfn) \
		{ \
			/* __current_alloclevel = 0; */ \
			/* zero the site now the alloc action is completed, even if it was already set */ \
			__current_allocsite = (void*)0; \
			__current_allocfn = (void*)0; \
			__current_allocsz = 0; \
		} \
		if (set_currently_allocating) __currently_allocating = 0; \
		return real_retval; \
	}

#define make_free_caller_wrapper(name) \
	void __real_ ## name (void *obj); \
	void __wrap_ ## name (void *obj) \
	{ \
		if (__generic_heap_check_for_free_cancellation(obj, __real_ ## name)) return; \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		__real_ ## name( obj ); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
	}

#define make_suballocator_free_caller_wrapper(name, alloc_name) \
	void __real_ ## name (void *obj); \
	void __wrap_ ## name (void *obj) \
	{ \
		assert(alloc_name ## _alloclevel); \
		if (__generic_heap_check_for_free_cancellation(obj, __real_ ## name)) return; \
		_Bool we_are_toplevel_free; \
		if (&__currently_freeing && !__currently_freeing) we_are_toplevel_free = 1; \
		else we_are_toplevel_free = 0; \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 1; \
		__real_ ## name( obj ); \
		__unindex_small_alloc(obj, alloc_name ## _alloclevel); \
		if (&__currently_freeing && we_are_toplevel_free) __currently_freeing = 0; \
	}

/* We also have some macros for generating callee wrappers. These are what 
 * do the indexing, at least logically. Being "callee" wrapper, we only 
 * generate them for objects that really do define the given allocator.
 * 
 * Logically, indexing operations belong here: we should actually invoke
 * the indexing hooks from this wrapper. Currently this isn't what happens.
 * Instead:
 * 
 * - "deep" allocators get the indexing done on the caller side (see above);
 *
 * - wrappers around the system malloc get hte indexing done in the preload 
 *   malloc;
 *
 * - objects which define their own malloc get the callee wrappers from
 *   liballocs_nonshared.a, which is using a mashup of this style of __wrap_*
 *   and the mallochooks stuff (in nonshared_hook_wrappers.c).
 *
 * So there is a gap to close off here: we should do the indexing here,
 * and only rely on the preload as a "special case" albeit the common case,
 * where libc supplies the malloc but is not itself built via us. We should
 * generate the "struct allocator" instance here. And we should dogfood these
 * macros to generate the actual preload stuff.
 *
 * Note that to do this properly, we need to distinguish actual alloc
 * functions from wrappers. Currently LIBALLOCS_ALLOC_FNS really refers
 * to wrappers; for your own actual allocators, they need to be a suballoc.
 */
#define make_callee_wrapper(name, rettype) \
	rettype __wrap___real_ ## name ( arglist_ ## name (make_argdecl) ) \
	{ \
		static rettype (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		rettype real_retval; \
		real_retval = real_ ## name( arglist_ ## name (make_argname) ); \
		return real_retval; \
	}
#define make_void_callee_wrapper(name) \
	void __wrap___real_ ## name( arglist_ ## name (make_argdecl) ) \
	{ \
		void (*real_ ## name)( arglist_ ## name (make_argtype) ); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, "__real_" #name); \
		if (!real_ ## name) real_ ## name = fake_dlsym(RTLD_DEFAULT, #name); /* probably infinite regress... */ \
		if (!real_ ## name) abort(); \
		real_ ## name( arglist_ ## name (make_argname) ); \
	}
