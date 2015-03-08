#define assert_rcu_or_pool_mutex()					\
	rcu_lockdep_assert(rcu_read_lock_sched_held() ||		\
			   lockdep_is_held(&wq_pool_mutex),		\
			   "sched RCU or wq_pool_mutex should be held")

#define assert_rcu_or_wq_mutex(wq)					\
	rcu_lockdep_assert(rcu_read_lock_sched_held() ||		\
			   lockdep_is_held(&wq->mutex),			\
			   "sched RCU or wq->mutex should be held")

#define for_each_cpu_worker_pool(pool, cpu)				\
	for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0];		\
	     (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; \
	     (pool)++)
#define for_each_pool(pool, pi)						\
	idr_for_each_entry(&worker_pool_idr, pool, pi)			\
		if (({ assert_rcu_or_pool_mutex(); false; })) { }	\
		else
#define for_each_pool_worker(worker, pool)				\
	list_for_each_entry((worker), &(pool)->workers, node)		\
		if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } \
		else
#define for_each_pwq(pwq, wq)						\
	list_for_each_entry_rcu((pwq), &(wq)->pwqs, pwqs_node)		\
		if (({ assert_rcu_or_wq_mutex(wq); false; })) { }	\
		else
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define CGROUP_PIDLIST_DESTROY_DELAY	HZ

#define CGROUP_FILE_NAME_MAX		(MAX_CGROUP_TYPE_NAMELEN +	\
					 MAX_CFTYPE_NAME + 2)

#define cgroup_assert_mutex_or_rcu_locked()				\
	rcu_lockdep_assert(rcu_read_lock_held() ||			\
			   lockdep_is_held(&cgroup_mutex),		\
			   "cgroup_mutex or RCU read lock required");

#define for_each_css(css, ssid, cgrp)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT; (ssid)++)	\
		if (!((css) = rcu_dereference_check(			\
				(cgrp)->subsys[(ssid)],			\
				lockdep_is_held(&cgroup_mutex)))) { }	\
		else

#define for_each_e_css(css, ssid, cgrp)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT; (ssid)++)	\
		if (!((css) = cgroup_e_css(cgrp, cgroup_subsys[(ssid)]))) \
			;						\
		else

#define for_each_subsys(ss, ssid)					\
	for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT &&		\
	     (((ss) = cgroup_subsys[ssid]) || true); (ssid)++)

/* iterate across the hierarchies */
#define for_each_root(root)						\
	list_for_each_entry((root), &cgroup_roots, root_list)

/* iterate over child cgrps, lock should be held throughout iteration */
#define cgroup_for_each_live_child(child, cgrp)				\
	list_for_each_entry((child), &(cgrp)->self.children, self.sibling) \
		if (({ lockdep_assert_held(&cgroup_mutex);		\
		       cgroup_is_dead(child); }))			\
			;						\
		else

#define MODULE_ALIAS_CRYPTO(name)	\
		__MODULE_INFO(alias, alias_userspace, name);	\
		__MODULE_INFO(alias, alias_crypto, "crypto-" name)

/*
 * Algorithm masks and types.
 */
#define CRYPTO_ALG_TYPE_MASK		0x0000000f
#define CRYPTO_ALG_TYPE_CIPHER		0x00000001
#define CRYPTO_ALG_TYPE_COMPRESS	0x00000002
#define CRYPTO_ALG_TYPE_AEAD		0x00000003
#define CRYPTO_ALG_TYPE_BLKCIPHER	0x00000004
#define CRYPTO_ALG_TYPE_ABLKCIPHER	0x00000005
#define CRYPTO_ALG_TYPE_GIVCIPHER	0x00000006
#define CRYPTO_ALG_TYPE_DIGEST		0x00000008
#define CRYPTO_ALG_TYPE_HASH		0x00000008
#define CRYPTO_ALG_TYPE_SHASH		0x00000009
#define CRYPTO_ALG_TYPE_AHASH		0x0000000a
#define CRYPTO_ALG_TYPE_RNG		0x0000000c
#define CRYPTO_ALG_TYPE_PCOMPRESS	0x0000000f

#define CRYPTO_ALG_TYPE_HASH_MASK	0x0000000e
#define CRYPTO_ALG_TYPE_AHASH_MASK	0x0000000c
#define CRYPTO_ALG_TYPE_BLKCIPHER_MASK	0x0000000c

#define CRYPTO_ALG_LARVAL		0x00000010
#define CRYPTO_ALG_DEAD			0x00000020
#define CRYPTO_ALG_DYING		0x00000040
#define CRYPTO_ALG_ASYNC		0x00000080

/*
 * Set this bit if and only if the algorithm requires another algorithm of
 * the same type to handle corner cases.
 */
#define CRYPTO_ALG_NEED_FALLBACK	0x00000100

/*
 * This bit is set for symmetric key ciphers that have already been wrapped
 * with a generic IV generator to prevent them from being wrapped again.
 */
#define CRYPTO_ALG_GENIV		0x00000200

/*
 * Set if the algorithm has passed automated run-time testing.  Note that
 * if there is no run-time testing for a given algorithm it is considered
 * to have passed.
 */

#define CRYPTO_ALG_TESTED		0x00000400

/*
 * Set if the algorithm is an instance that is build from templates.
 */
#define CRYPTO_ALG_INSTANCE		0x00000800

/* Set this bit if the algorithm provided is hardware accelerated but
 * not available to userspace via instruction set or so.
 */
#define CRYPTO_ALG_KERN_DRIVER_ONLY	0x00001000

/*
 * Transform masks and values (for crt_flags).
 */
#define CRYPTO_TFM_REQ_MASK		0x000fff00
#define CRYPTO_TFM_RES_MASK		0xfff00000

#define CRYPTO_TFM_REQ_WEAK_KEY		0x00000100
#define CRYPTO_TFM_REQ_MAY_SLEEP	0x00000200
#define CRYPTO_TFM_REQ_MAY_BACKLOG	0x00000400
#define CRYPTO_TFM_RES_WEAK_KEY		0x00100000
#define CRYPTO_TFM_RES_BAD_KEY_LEN   	0x00200000
#define CRYPTO_TFM_RES_BAD_KEY_SCHED 	0x00400000
#define CRYPTO_TFM_RES_BAD_BLOCK_LEN 	0x00800000
#define CRYPTO_TFM_RES_BAD_FLAGS 	0x01000000

/*
 * Miscellaneous stuff.
 */
#define CRYPTO_MAX_ALG_NAME		64

/*
 * The macro CRYPTO_MINALIGN_ATTR (along with the void * type in the actual
 * declaration) is used to ensure that the crypto_tfm context structure is
 * aligned correctly for the given architecture so that there are no alignment
 * faults for C data types.  In particular, this is required on platforms such
 * as arm where pointers are 32-bit aligned but there are data types such as
 * u64 which require 64-bit alignment.
 */
#define CRYPTO_MINALIGN ARCH_KMALLOC_MINALIGN

#define CRYPTO_MINALIGN_ATTR __attribute__ ((__aligned__(CRYPTO_MINALIGN)))

#define work_data_bits(work) ((unsigned long *)(&(work)->data))

#define WORK_DATA_INIT()	ATOMIC_LONG_INIT(WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC)

#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),

#define __WORK_INITIALIZER(n, f) {					\
	.data = WORK_DATA_STATIC_INIT(),				\
	.entry	= { &(n).entry, &(n).entry },				\
	.func = (f),							\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))				\
	}

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER(delayed_work_timer_fn,		\
				     0, (unsigned long)&(n),		\
				     (tflags) | TIMER_IRQSAFE),		\
	}

#define DECLARE_WORK(n, f)						\
	struct work_struct n = __WORK_INITIALIZER(n, f)

#define DECLARE_DELAYED_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, 0)

#define DECLARE_DEFERRABLE_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, TIMER_DEFERRABLE)

#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, #_work, &__key, 0); \
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)

#define INIT_WORK(_work, _func)						\
	do {								\
		__INIT_WORK((_work), (_func), 0);			\
	} while (0)

#define INIT_WORK_ONSTACK(_work, _func)					\
	do {								\
		__INIT_WORK((_work), (_func), 1);			\
	} while (0)

#define __INIT_DELAYED_WORK(_work, _func, _tflags)			\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		__setup_timer(&(_work)->timer, delayed_work_timer_fn,	\
			      (unsigned long)(_work),			\
			      (_tflags) | TIMER_IRQSAFE);		\
	} while (0)

#define __INIT_DELAYED_WORK_ONSTACK(_work, _func, _tflags)		\
	do {								\
		INIT_WORK_ONSTACK(&(_work)->work, (_func));		\
		__setup_timer_on_stack(&(_work)->timer,			\
				       delayed_work_timer_fn,		\
				       (unsigned long)(_work),		\
				       (_tflags) | TIMER_IRQSAFE);	\
	} while (0)

#define INIT_DELAYED_WORK(_work, _func)					\
	__INIT_DELAYED_WORK(_work, _func, 0)

#define INIT_DELAYED_WORK_ONSTACK(_work, _func)				\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, 0)

#define INIT_DEFERRABLE_WORK(_work, _func)				\
	__INIT_DELAYED_WORK(_work, _func, TIMER_DEFERRABLE)

#define INIT_DEFERRABLE_WORK_ONSTACK(_work, _func)			\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, TIMER_DEFERRABLE)

/**
 * work_pending - Find out whether a work item is currently pending
 * @work: The work item in question
 */
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))

/**
 * delayed_work_pending - Find out whether a delayable work item is currently
 * pending
 * @work: The work item in question
 */
#define delayed_work_pending(w) \
	work_pending(&(w)->work)

#define WQ_UNBOUND_MAX_ACTIVE	\
	max_t(int, WQ_MAX_ACTIVE, num_possible_cpus() * WQ_MAX_UNBOUND_PER_CPU)




#define create_workqueue(name)						\
	alloc_workqueue("%s", WQ_MEM_RECLAIM, 1, (name))
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", WQ_FREEZABLE | WQ_UNBOUND | WQ_MEM_RECLAIM, \
			1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)

#define CPU_ONLINE		0x0002 /* CPU (unsigned)v is up */
#define CPU_UP_PREPARE		0x0003 /* CPU (unsigned)v coming up */
#define CPU_UP_CANCELED		0x0004 /* CPU (unsigned)v NOT coming up */
#define CPU_DOWN_PREPARE	0x0005 /* CPU (unsigned)v going down */
#define CPU_DOWN_FAILED		0x0006 /* CPU (unsigned)v NOT going down */
#define CPU_DEAD		0x0007 /* CPU (unsigned)v dead */
#define CPU_DYING		0x0008 /* CPU (unsigned)v not running any task,
					* not handling interrupts, soon dead.
					* Called on the dying cpu, interrupts
					* are already disabled. Must not
					* sleep, must not fail */
#define CPU_POST_DEAD		0x0009 /* CPU (unsigned)v dead, cpu_hotplug
					* lock is dropped */
#define CPU_STARTING		0x000A /* CPU (unsigned)v soon running.
					* Called on the new cpu, just before
					* enabling interrupts. Must not sleep,
					* must not fail */

#ifdef CONFIG_DEBUG_SET_MODULE_RONX
# define debug_align(X) ALIGN(X, PAGE_SIZE)
#else
# define debug_align(X) (X)
#endif

/*
 * Given BASE and SIZE this macro calculates the number of pages the
 * memory regions occupies
 */
#define MOD_NUMBER_OF_PAGES(BASE, SIZE) (((SIZE) > 0) ?		\
		(PFN_DOWN((unsigned long)(BASE) + (SIZE) - 1) -	\
			 PFN_DOWN((unsigned long)BASE) + 1)	\
		: (0UL))

/* If this is set, the section belongs in the init part of the module */
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG-1))

/*
 * Mutex protects:
 * 1) List of modules (also safely readable with preempt_disable),
 * 2) module_use links,
 * 3) module_addr_min/module_addr_max.
 * (delete and add uses RCU list operations). */
DEFINE_MUTEX(module_mutex);
EXPORT_SYMBOL_GPL(module_mutex);
static LIST_HEAD(modules);
#ifdef CONFIG_KGDB_KDB
struct list_head *kdb_modules = &modules; /* kdb needs the list of modules */
#endif /* CONFIG_KGDB_KDB */

#ifdef CONFIG_MODULE_SIG
#endif
#ifdef CONFIG_MODULE_SIG_FORCE
static bool sig_enforce = true;
#else
static bool sig_enforce = false;
#endif

#define param_check_bool_enable_only param_check_bool

#ifndef CONFIG_MODVERSIONS
#define symversion(base, idx) NULL
#else
#define symversion(base, idx) ((base != NULL) ? ((base) + (idx)) : NULL)
#endif



#define FLAGS_SHARED		0x01
#define FLAGS_CLOCKRT		0x02
#define FLAGS_HAS_TIMEOUT	0x04

#define for_each_kimage_entry(image, ptr, entry) \
	for (ptr = &image->head; (entry = *ptr) && !(entry & IND_DONE); \
		ptr = (entry & IND_INDIRECTION) ? \
			phys_to_virt((entry & PAGE_MASK)) : ptr + 1)

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

#define __si_special(priv) \
	((priv) ? SEND_SIG_PRIV : SEND_SIG_NOINFO)

#define cpuset_for_each_child(child_cs, pos_css, parent_cs)		\
	css_for_each_child((pos_css), &(parent_cs)->css)		\
		if (is_cpuset_online(((child_cs) = css_cs((pos_css)))))

/**
 * cpuset_for_each_descendant_pre - pre-order walk of a cpuset's descendants
 * @des_cs: loop cursor pointing to the current descendant
 * @pos_css: used for iteration
 * @root_cs: target cpuset to walk ancestor of
 *
 * Walk @des_cs through the online descendants of @root_cs.  Must be used
 * with RCU read locked.  The caller may modify @pos_css by calling
 * css_rightmost_descendant() to skip subtree.  @root_cs is included in the
 * iteration and the first node to be visited.
 */
#define cpuset_for_each_descendant_pre(des_cs, pos_css, root_cs)	\
	css_for_each_descendant_pre((pos_css), &(root_cs)->css)		\
		if (is_cpuset_online(((des_cs) = css_cs((pos_css)))))

#undef	MODULE_PARAM_PREFIX
#define	MODULE_PARAM_PREFIX "kdb."

static int kdb_cmd_enabled = CONFIG_KDB_DEFAULT_ENABLE;
module_param_named(cmd_enable, kdb_cmd_enabled, int, 0600);

#define GREP_LEN 256
char kdb_grep_string[GREP_LEN];
int kdb_grepping_flag;
EXPORT_SYMBOL(kdb_grepping_flag);
int kdb_grep_leading;
int kdb_grep_trailing;

/*
 * Kernel debugger state flags
 */
int kdb_flags;
atomic_t kdb_event;

/*
 * kdb_lock protects updates to kdb_initial_cpu.  Used to
 * single thread processors through the kernel debugger.
 */
int kdb_initial_cpu = -1;	/* cpu number that owns kdb */
int kdb_nextline = 1;
int kdb_state;			/* General KDB state */

struct task_struct *kdb_current_task;
EXPORT_SYMBOL(kdb_current_task);
struct pt_regs *kdb_current_regs;

const char *kdb_diemsg;
static int kdb_go_count;
#ifdef CONFIG_KDB_CONTINUE_CATASTROPHIC
static unsigned int kdb_continue_catastrophic =
	CONFIG_KDB_CONTINUE_CATASTROPHIC;
#else
static unsigned int kdb_continue_catastrophic;
#endif

/* kdb_commands describes the available commands. */
static kdbtab_t *kdb_commands;
#define KDB_BASE_CMD_MAX 50
static int kdb_max_commands = KDB_BASE_CMD_MAX;
static kdbtab_t kdb_base_commands[KDB_BASE_CMD_MAX];
#define for_each_kdbcmd(cmd, num)					\
	for ((cmd) = kdb_base_commands, (num) = 0;			\
	     num < kdb_max_commands;					\
	     num++, num == KDB_BASE_CMD_MAX ? cmd = kdb_commands : cmd++)

typedef struct _kdbmsg {
	int	km_diag;	/* kdb diagnostic */
	char	*km_msg;	/* Corresponding message text */
} kdbmsg_t;


static kdbmsg_t kdbmsgs[] = {
	KDBMSG(NOTFOUND, "Command Not Found"),
	KDBMSG(ARGCOUNT, "Improper argument count, see usage."),
	KDBMSG(BADWIDTH, "Illegal value for BYTESPERWORD use 1, 2, 4 or 8, "
	       "8 is only allowed on 64 bit systems"),
	KDBMSG(BADRADIX, "Illegal value for RADIX use 8, 10 or 16"),
	KDBMSG(NOTENV, "Cannot find environment variable"),
	KDBMSG(NOENVVALUE, "Environment variable should have value"),
	KDBMSG(NOTIMP, "Command not implemented"),
	KDBMSG(ENVFULL, "Environment full"),
	KDBMSG(ENVBUFFULL, "Environment buffer full"),
	KDBMSG(TOOMANYBPT, "Too many breakpoints defined"),
#ifdef CONFIG_CPU_XSCALE
	KDBMSG(TOOMANYDBREGS, "More breakpoints than ibcr registers defined"),
#else
	KDBMSG(TOOMANYDBREGS, "More breakpoints than db registers defined"),
#endif
	KDBMSG(DUPBPT, "Duplicate breakpoint address"),
	KDBMSG(BPTNOTFOUND, "Breakpoint not found"),
	KDBMSG(BADMODE, "Invalid IDMODE"),
	KDBMSG(BADINT, "Illegal numeric value"),
	KDBMSG(INVADDRFMT, "Invalid symbolic address format"),
	KDBMSG(BADREG, "Invalid register name"),
	KDBMSG(BADCPUNUM, "Invalid cpu number"),
	KDBMSG(BADLENGTH, "Invalid length field"),
	KDBMSG(NOBP, "No Breakpoint exists"),
	KDBMSG(BADADDR, "Invalid address"),
	KDBMSG(NOPERM, "Permission denied"),
};
#undef KDBMSG

static const int __nkdb_err = ARRAY_SIZE(kdbmsgs);


/*
 * Initial environment.   This is all kept static and local to
 * this file.   We don't want to rely on the memory allocation
 * mechanisms in the kernel, so we use a very limited allocate-only
 * heap for new and altered environment variables.  The entire
 * environment is limited to a fixed number of entries (add more
 * to __env[] if required) and a fixed amount of heap (add more to
 * KDB_ENVBUFSIZE if required).
 */

static char *__env[] = {
#if defined(CONFIG_SMP)
 "PROMPT=[%d]kdb> ",
#else
 "PROMPT=kdb> ",
#endif
 "MOREPROMPT=more> ",
 "RADIX=16",
 "MDCOUNT=8",			/* lines of md output */
 KDB_PLATFORM_ENV,
 "DTABCOUNT=30",
 "NOSECT=1",
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
};

static const int __nenv = ARRAY_SIZE(__env);

struct task_struct *kdb_curr_task(int cpu)
{
	struct task_struct *p = curr_task(cpu);
#ifdef	_TIF_MCA_INIT
	if ((task_thread_info(p)->flags & _TIF_MCA_INIT) && KDB_TSK(cpu))
		p = krp->p;
#endif
	return p;
}

/*
 * Check whether the flags of the current command and the permissions
 * of the kdb console has allow a command to be run.
 */
static inline bool kdb_check_flags(kdb_cmdflags_t flags, int permissions,
				   bool no_args)
{
	/* permissions comes from userspace so needs massaging slightly */
	permissions &= KDB_ENABLE_MASK;
	permissions |= KDB_ENABLE_ALWAYS_SAFE;

	/* some commands change group when launched with no arguments */
	if (no_args)
		permissions |= permissions << KDB_ENABLE_NO_ARGS_SHIFT;

	flags |= KDB_ENABLE_ALL;

	return permissions & flags;
}

/*
 * kdbgetenv - This function will return the character string value of
 *	an environment variable.
 * Parameters:
 *	match	A character string representing an environment variable.
 * Returns:
 *	NULL	No environment variable matches 'match'
 *	char*	Pointer to string value of environment variable.
 */
char *kdbgetenv(const char *match)
{
	char **ep = __env;
	int matchlen = strlen(match);
	int i;

	for (i = 0; i < __nenv; i++) {
		char *e = *ep++;

		if (!e)
			continue;

		if ((strncmp(match, e, matchlen) == 0)
		 && ((e[matchlen] == '\0')
		   || (e[matchlen] == '='))) {
			char *cp = strchr(e, '=');
			return cp ? ++cp : "";
		}
	}
	return NULL;
}

/*
 * kdballocenv - This function is used to allocate bytes for
 *	environment entries.
 * Parameters:
 *	match	A character string representing a numeric value
 * Outputs:
 *	*value  the unsigned long representation of the env variable 'match'
 * Returns:
 *	Zero on success, a kdb diagnostic on failure.
 * Remarks:
 *	We use a static environment buffer (envbuffer) to hold the values
 *	of dynamically generated environment variables (see kdb_set).  Buffer
 *	space once allocated is never free'd, so over time, the amount of space
 *	(currently 512 bytes) will be exhausted if env variables are changed
 *	frequently.
 */
static char *kdballocenv(size_t bytes)
{
#define	KDB_ENVBUFSIZE	512
	static char envbuffer[KDB_ENVBUFSIZE];
	static int envbufsize;
	char *ep = NULL;

	if ((KDB_ENVBUFSIZE - envbufsize) >= bytes) {
		ep = &envbuffer[envbufsize];
		envbufsize += bytes;
	}
	return ep;
}

/*
 * kdbgetulenv - This function will return the value of an unsigned
 *	long-valued environment variable.
 * Parameters:
 *	match	A character string representing a numeric value
 * Outputs:
 *	*value  the unsigned long represntation of the env variable 'match'
 * Returns:
 *	Zero on success, a kdb diagnostic on failure.
 */
static int kdbgetulenv(const char *match, unsigned long *value)
{
	char *ep;

	ep = kdbgetenv(match);
	if (!ep)
		return KDB_NOTENV;
	if (strlen(ep) == 0)
		return KDB_NOENVVALUE;

	*value = simple_strtoul(ep, NULL, 0);

	return 0;
}

/*
 * kdbgetintenv - This function will return the value of an
 *	integer-valued environment variable.
 * Parameters:
 *	match	A character string representing an integer-valued env variable
 * Outputs:
 *	*value  the integer representation of the environment variable 'match'
 * Returns:
 *	Zero on success, a kdb diagnostic on failure.
 */
int kdbgetintenv(const char *match, int *value)
{
	unsigned long val;
	int diag;

	diag = kdbgetulenv(match, &val);
	if (!diag)
		*value = (int) val;
	return diag;
}

/*
 * kdbgetularg - This function will convert a numeric string into an
 *	unsigned long value.
 * Parameters:
 *	arg	A character string representing a numeric value
 * Outputs:
 *	*value  the unsigned long represntation of arg.
 * Returns:
 *	Zero on success, a kdb diagnostic on failure.
 */
int kdbgetularg(const char *arg, unsigned long *value)
{
	char *endp;
	unsigned long val;

	val = simple_strtoul(arg, &endp, 0);

	if (endp == arg) {
		/*
		 * Also try base 16, for us folks too lazy to type the
		 * leading 0x...
		 */
		val = simple_strtoul(arg, &endp, 16);
		if (endp == arg)
			return KDB_BADINT;
	}

	*value = val;

	return 0;
}

int kdbgetu64arg(const char *arg, u64 *value)
{
	char *endp;
	u64 val;

	val = simple_strtoull(arg, &endp, 0);

	if (endp == arg) {

		val = simple_strtoull(arg, &endp, 16);
		if (endp == arg)
			return KDB_BADINT;
	}

	*value = val;

	return 0;
}

/*
 * kdb_set - This function implements the 'set' command.  Alter an
 *	existing environment variable or create a new one.
 */
int kdb_set(int argc, const char **argv)
{
	int i;
	char *ep;
	size_t varlen, vallen;

	/*
	 * we can be invoked two ways:
	 *   set var=value    argv[1]="var", argv[2]="value"
	 *   set var = value  argv[1]="var", argv[2]="=", argv[3]="value"
	 * - if the latter, shift 'em down.
	 */
	if (argc == 3) {
		argv[2] = argv[3];
		argc--;
	}

	if (argc != 2)
		return KDB_ARGCOUNT;

	/*
	 * Check for internal variables
	 */
	if (strcmp(argv[1], "KDBDEBUG") == 0) {
		unsigned int debugflags;
		char *cp;

		debugflags = simple_strtoul(argv[2], &cp, 0);
		if (cp == argv[2] || debugflags & ~KDB_DEBUG_FLAG_MASK) {
			kdb_printf("kdb: illegal debug flags '%s'\n",
				    argv[2]);
			return 0;
		}
		kdb_flags = (kdb_flags &
			     ~(KDB_DEBUG_FLAG_MASK << KDB_DEBUG_FLAG_SHIFT))
			| (debugflags << KDB_DEBUG_FLAG_SHIFT);

		return 0;
	}

	/*
	 * Tokenizer squashed the '=' sign.  argv[1] is variable
	 * name, argv[2] = value.
	 */
	varlen = strlen(argv[1]);
	vallen = strlen(argv[2]);
	ep = kdballocenv(varlen + vallen + 2);
	if (ep == (char *)0)
		return KDB_ENVBUFFULL;

	sprintf(ep, "%s=%s", argv[1], argv[2]);

	ep[varlen+vallen+1] = '\0';

	for (i = 0; i < __nenv; i++) {
		if (__env[i]
		 && ((strncmp(__env[i], argv[1], varlen) == 0)
		   && ((__env[i][varlen] == '\0')
		    || (__env[i][varlen] == '=')))) {
			__env[i] = ep;
			return 0;
		}
	}

	/*
	 * Wasn't existing variable.  Fit into slot.
	 */
	for (i = 0; i < __nenv-1; i++) {
		if (__env[i] == (char *)0) {
			__env[i] = ep;
			return 0;
		}
	}

	return KDB_ENVFULL;
}

static int kdb_check_regs(void)
{
	if (!kdb_current_regs) {
		kdb_printf("No current kdb registers."
			   "  You may need to select another task\n");
		return KDB_BADREG;
	}
	return 0;
}

/*
 * kdbgetaddrarg - This function is responsible for parsing an
 *	address-expression and returning the value of the expression,
 *	symbol name, and offset to the caller.
 *
 *	The argument may consist of a numeric value (decimal or
 *	hexidecimal), a symbol name, a register name (preceded by the
 *	percent sign), an environment variable with a numeric value
 *	(preceded by a dollar sign) or a simple arithmetic expression
 *	consisting of a symbol name, +/-, and a numeric constant value
 *	(offset).
 * Parameters:
 *	argc	- count of arguments in argv
 *	argv	- argument vector
 *	*nextarg - index to next unparsed argument in argv[]
 *	regs	- Register state at time of KDB entry
 * Outputs:
 *	*value	- receives the value of the address-expression
 *	*offset - receives the offset specified, if any
 *	*name   - receives the symbol name, if any
 *	*nextarg - index to next unparsed argument in argv[]
 * Returns:
 *	zero is returned on success, a kdb diagnostic code is
 *      returned on error.
 */
int kdbgetaddrarg(int argc, const char **argv, int *nextarg,
		  unsigned long *value,  long *offset,
		  char **name)
{
	unsigned long addr;
	unsigned long off = 0;
	int positive;
	int diag;
	int found = 0;
	char *symname;
	char symbol = '\0';
	char *cp;
	kdb_symtab_t symtab;

	/*
	 * If the enable flags prohibit both arbitrary memory access
	 * and flow control then there are no reasonable grounds to
	 * provide symbol lookup.
	 */
	if (!kdb_check_flags(KDB_ENABLE_MEM_READ | KDB_ENABLE_FLOW_CTRL,
			     kdb_cmd_enabled, false))
		return KDB_NOPERM;

	/*
	 * Process arguments which follow the following syntax:
	 *
	 *  symbol | numeric-address [+/- numeric-offset]
	 *  %register
	 *  $environment-variable
	 */

	if (*nextarg > argc)
		return KDB_ARGCOUNT;

	symname = (char *)argv[*nextarg];

	/*
	 * If there is no whitespace between the symbol
	 * or address and the '+' or '-' symbols, we
	 * remember the character and replace it with a
	 * null so the symbol/value can be properly parsed
	 */
	cp = strpbrk(symname, "+-");
	if (cp != NULL) {
		symbol = *cp;
		*cp++ = '\0';
	}

	if (symname[0] == '$') {
		diag = kdbgetulenv(&symname[1], &addr);
		if (diag)
			return diag;
	} else if (symname[0] == '%') {
		diag = kdb_check_regs();
		if (diag)
			return diag;
		/* Implement register values with % at a later time as it is
		 * arch optional.
		 */
		return KDB_NOTIMP;
	} else {
		found = kdbgetsymval(symname, &symtab);
		if (found) {
			addr = symtab.sym_start;
		} else {
			diag = kdbgetularg(argv[*nextarg], &addr);
			if (diag)
				return diag;
		}
	}

	if (!found)
		found = kdbnearsym(addr, &symtab);

	(*nextarg)++;

	if (name)
		*name = symname;
	if (value)
		*value = addr;
	if (offset && name && *name)
		*offset = addr - symtab.sym_start;

	if ((*nextarg > argc)
	 && (symbol == '\0'))
		return 0;

	/*
	 * check for +/- and offset
	 */

	if (symbol == '\0') {
		if ((argv[*nextarg][0] != '+')
		 && (argv[*nextarg][0] != '-')) {
			/*
			 * Not our argument.  Return.
			 */
			return 0;
		} else {
			positive = (argv[*nextarg][0] == '+');
			(*nextarg)++;
		}
	} else
		positive = (symbol == '+');

	/*
	 * Now there must be an offset!
	 */
	if ((*nextarg > argc)
	 && (symbol == '\0')) {
		return KDB_INVADDRFMT;
	}

	if (!symbol) {
		cp = (char *)argv[*nextarg];
		(*nextarg)++;
	}

	diag = kdbgetularg(cp, &off);
	if (diag)
		return diag;

	if (!positive)
		off = -off;

	if (offset)
		*offset += off;

	if (value)
		*value += off;

	return 0;
}

#define down_console_sem() do { \
	down(&console_sem);\
	mutex_acquire(&console_lock_dep_map, 0, 0, _RET_IP_);\
} while (0)

static int __down_trylock_console_sem(unsigned long ip)
{
	if (down_trylock(&console_sem))
		return 1;
	mutex_acquire(&console_lock_dep_map, 0, 1, ip);
	return 0;
}
#define down_trylock_console_sem() __down_trylock_console_sem(_RET_IP_)

#define up_console_sem() do { \
	mutex_release(&console_lock_dep_map, 1, _RET_IP_);\
	up(&console_sem);\
} while (0)

/*
 * This is used for debugging the mess that is the VT code by
 * keeping track if we have the console semaphore held. It's
 * definitely not the perfect debug tool (we don't know if _WE_
 * hold it and are racing, but it helps tracking those weird code
 * paths in the console code where we end up in places I want
 * locked without the console sempahore held).
 */
static int console_locked, console_suspended;

/*
 * If exclusive_console is non-NULL then only this console is to be printed to.
 */
static struct console *exclusive_console;

/*
 *	Array of consoles built from command line options (console=)
 */

#define MAX_CMDLINECONSOLES 8

static struct console_cmdline console_cmdline[MAX_CMDLINECONSOLES];

static int selected_console = -1;
static int preferred_console = -1;
int console_set_on_cmdline;
EXPORT_SYMBOL(console_set_on_cmdline);

/* Flag: console code may call schedule() */
static int console_may_schedule;

#define PREFIX_MAX		32
#define LOG_LINE_MAX		(1024 - PREFIX_MAX)

/* record buffer */
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
#define LOG_ALIGN 4
#else
#define LOG_ALIGN __alignof__(struct printk_log)
#endif
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
static char *log_buf = __log_buf;
static u32 log_buf_len = __LOG_BUF_LEN;

/* Return log buffer address */
char *log_buf_addr_get(void)
{
	return log_buf;
}

/* Return log buffer size */
u32 log_buf_len_get(void)
{
	return log_buf_len;
}

/* human readable text of the record */
static char *log_text(const struct printk_log *msg)
{
	return (char *)msg + sizeof(struct printk_log);
}

/* optional key/value pair dictionary attached to the record */
static char *log_dict(const struct printk_log *msg)
{
	return (char *)msg + sizeof(struct printk_log) + msg->text_len;
}

/* get record by index; idx must point to valid msg */
static struct printk_log *log_from_idx(u32 idx)
{
	struct printk_log *msg = (struct printk_log *)(log_buf + idx);

	/*
	 * A length == 0 record is the end of buffer marker. Wrap around and
	 * read the message at the start of the buffer.
	 */
	if (!msg->len)
		return (struct printk_log *)log_buf;
	return msg;
}

/* get next record; idx must point to valid msg */
static u32 log_next(u32 idx)
{
	struct printk_log *msg = (struct printk_log *)(log_buf + idx);

	/* length == 0 indicates the end of the buffer; wrap */
	/*
	 * A length == 0 record is the end of buffer marker. Wrap around and
	 * read the message at the start of the buffer as *this* one, and
	 * return the one after that.
	 */
	if (!msg->len) {
		msg = (struct printk_log *)log_buf;
		return msg->len;
	}
	return idx + msg->len;
}

/*
 * Check whether there is enough free space for the given message.
 *
 * The same values of first_idx and next_idx mean that the buffer
 * is either empty or full.
 *
 * If the buffer is empty, we must respect the position of the indexes.
 * They cannot be reset to the beginning of the buffer.
 */
static int logbuf_has_space(u32 msg_size, bool empty)
{
	u32 free;

	if (log_next_idx > log_first_idx || empty)
		free = max(log_buf_len - log_next_idx, log_first_idx);
	else
		free = log_first_idx - log_next_idx;

	/*
	 * We need space also for an empty header that signalizes wrapping
	 * of the buffer.
	 */
	return free >= msg_size + sizeof(struct printk_log);
}

static int log_make_free_space(u32 msg_size)
{
	while (log_first_seq < log_next_seq) {
		if (logbuf_has_space(msg_size, false))
			return 0;
		/* drop old messages until we have enough contiguous space */
		log_first_idx = log_next(log_first_idx);
		log_first_seq++;
	}

	/* sequence numbers are equal, so the log buffer is empty */
	if (logbuf_has_space(msg_size, true))
		return 0;

	return -ENOMEM;
}

/* compute the message size including the padding bytes */
static u32 msg_used_size(u16 text_len, u16 dict_len, u32 *pad_len)
{
	u32 size;

	size = sizeof(struct printk_log) + text_len + dict_len;
	*pad_len = (-size) & (LOG_ALIGN - 1);
	size += *pad_len;

	return size;
}

/*
 * Define how much of the log buffer we could take at maximum. The value
 * must be greater than two. Note that only half of the buffer is available
 * when the index points to the middle.
 */
#define MAX_LOG_TAKE_PART 4
static const char trunc_msg[] = "<truncated>";

static u32 truncate_msg(u16 *text_len, u16 *trunc_msg_len,
			u16 *dict_len, u32 *pad_len)
{
	/*
	 * The message should not take the whole buffer. Otherwise, it might
	 * get removed too soon.
	 */
	u32 max_text_len = log_buf_len / MAX_LOG_TAKE_PART;
	if (*text_len > max_text_len)
		*text_len = max_text_len;
	/* enable the warning message */
	*trunc_msg_len = strlen(trunc_msg);
	/* disable the "dict" completely */
	*dict_len = 0;
	/* compute the size again, count also the warning message */
	return msg_used_size(*text_len + *trunc_msg_len, 0, pad_len);
}

/* insert record into the buffer, discard old ones, update heads */
static int log_store(int facility, int level,
		     enum log_flags flags, u64 ts_nsec,
		     const char *dict, u16 dict_len,
		     const char *text, u16 text_len)
{
	struct printk_log *msg;
	u32 size, pad_len;
	u16 trunc_msg_len = 0;

	/* number of '\0' padding bytes to next message */
	size = msg_used_size(text_len, dict_len, &pad_len);

	if (log_make_free_space(size)) {
		/* truncate the message if it is too long for empty buffer */
		size = truncate_msg(&text_len, &trunc_msg_len,
				    &dict_len, &pad_len);
		/* survive when the log buffer is too small for trunc_msg */
		if (log_make_free_space(size))
			return 0;
	}

	if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
		/*
		 * This message + an additional empty header does not fit
		 * at the end of the buffer. Add an empty header with len == 0
		 * to signify a wrap around.
		 */
		memset(log_buf + log_next_idx, 0, sizeof(struct printk_log));
		log_next_idx = 0;
	}

	/* fill message */
	msg = (struct printk_log *)(log_buf + log_next_idx);
	memcpy(log_text(msg), text, text_len);
	msg->text_len = text_len;
	if (trunc_msg_len) {
		memcpy(log_text(msg) + text_len, trunc_msg, trunc_msg_len);
		msg->text_len += trunc_msg_len;
	}
	memcpy(log_dict(msg), dict, dict_len);
	msg->dict_len = dict_len;
	msg->facility = facility;
	msg->level = level & 7;
	msg->flags = flags & 0x1f;
	if (ts_nsec > 0)
		msg->ts_nsec = ts_nsec;
	else
		msg->ts_nsec = local_clock();
	memset(log_dict(msg) + dict_len, 0, pad_len);
	msg->len = size;

	/* insert message */
	log_next_idx += msg->len;
	log_next_seq++;

	return msg->text_len;
}

int dmesg_restrict = IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT);

static int syslog_action_restricted(int type)
{
	if (dmesg_restrict)
		return 1;
	/*
	 * Unless restricted, we allow "read all" and "get buffer size"
	 * for everybody.
	 */
	return type != SYSLOG_ACTION_READ_ALL &&
	       type != SYSLOG_ACTION_SIZE_BUFFER;
}

int check_syslog_permissions(int type, bool from_file)
{
	/*
	 * If this is from /proc/kmsg and we've already opened it, then we've
	 * already done the capabilities checks at open time.
	 */
	if (from_file && type != SYSLOG_ACTION_OPEN)
		return 0;

	if (syslog_action_restricted(type)) {
		if (capable(CAP_SYSLOG))
			return 0;
		/*
		 * For historical reasons, accept CAP_SYS_ADMIN too, with
		 * a warning.
		 */
		if (capable(CAP_SYS_ADMIN)) {
			pr_warn_once("%s (%d): Attempt to access syslog with "
				     "CAP_SYS_ADMIN but no CAP_SYSLOG "
				     "(deprecated).\n",
				 current->comm, task_pid_nr(current));
			return 0;
		}
		return -EPERM;
	}
	return security_syslog(type);
}


/* /dev/kmsg - userspace message inject/listen interface */
struct devkmsg_user {
	u64 seq;
	u32 idx;
	enum log_flags prev;
	struct mutex lock;
	char buf[8192];
};

static ssize_t devkmsg_write(struct kiocb *iocb, struct iov_iter *from)
{
	char *buf, *line;
	int i;
	int level = default_message_loglevel;
	int facility = 1;	/* LOG_USER */
	size_t len = iocb->ki_nbytes;
	ssize_t ret = len;

	if (len > LOG_LINE_MAX)
		return -EINVAL;
	buf = kmalloc(len+1, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	buf[len] = '\0';
	if (copy_from_iter(buf, len, from) != len) {
		kfree(buf);
		return -EFAULT;
	}

	/*
	 * Extract and skip the syslog prefix <[0-9]*>. Coming from userspace
	 * the decimal value represents 32bit, the lower 3 bit are the log
	 * level, the rest are the log facility.
	 *
	 * If no prefix or no userspace facility is specified, we
	 * enforce LOG_USER, to be able to reliably distinguish
	 * kernel-generated messages from userspace-injected ones.
	 */
	line = buf;
	if (line[0] == '<') {
		char *endp = NULL;

		i = simple_strtoul(line+1, &endp, 10);
		if (endp && endp[0] == '>') {
			level = i & 7;
			if (i >> 3)
				facility = i >> 3;
			endp++;
			len -= endp - line;
			line = endp;
		}
	}

	printk_emit(facility, level, NULL, 0, "%s", line);
	kfree(buf);
	return ret;
}

static ssize_t devkmsg_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct devkmsg_user *user = file->private_data;
	struct printk_log *msg;
	u64 ts_usec;
	size_t i;
	char cont = '-';
	size_t len;
	ssize_t ret;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret)
		return ret;
	raw_spin_lock_irq(&logbuf_lock);
	while (user->seq == log_next_seq) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			raw_spin_unlock_irq(&logbuf_lock);
			goto out;
		}

		raw_spin_unlock_irq(&logbuf_lock);
		ret = wait_event_interruptible(log_wait,
					       user->seq != log_next_seq);
		if (ret)
			goto out;
		raw_spin_lock_irq(&logbuf_lock);
	}

	if (user->seq < log_first_seq) {
		/* our last seen message is gone, return error and reset */
		user->idx = log_first_idx;
		user->seq = log_first_seq;
		ret = -EPIPE;
		raw_spin_unlock_irq(&logbuf_lock);
		goto out;
	}

	msg = log_from_idx(user->idx);
	ts_usec = msg->ts_nsec;
	do_div(ts_usec, 1000);

	/*
	 * If we couldn't merge continuation line fragments during the print,
	 * export the stored flags to allow an optional external merge of the
	 * records. Merging the records isn't always neccessarily correct, like
	 * when we hit a race during printing. In most cases though, it produces
	 * better readable output. 'c' in the record flags mark the first
	 * fragment of a line, '+' the following.
	 */
	if (msg->flags & LOG_CONT && !(user->prev & LOG_CONT))
		cont = 'c';
	else if ((msg->flags & LOG_CONT) ||
		 ((user->prev & LOG_CONT) && !(msg->flags & LOG_PREFIX)))
		cont = '+';

	len = sprintf(user->buf, "%u,%llu,%llu,%c;",
		      (msg->facility << 3) | msg->level,
		      user->seq, ts_usec, cont);
	user->prev = msg->flags;

	/* escape non-printable characters */
	for (i = 0; i < msg->text_len; i++) {
		unsigned char c = log_text(msg)[i];

		if (c < ' ' || c >= 127 || c == '\\')
			len += sprintf(user->buf + len, "\\x%02x", c);
		else
			user->buf[len++] = c;
	}
	user->buf[len++] = '\n';

	if (msg->dict_len) {
		bool line = true;

		for (i = 0; i < msg->dict_len; i++) {
			unsigned char c = log_dict(msg)[i];

			if (line) {
				user->buf[len++] = ' ';
				line = false;
			}

			if (c == '\0') {
				user->buf[len++] = '\n';
				line = true;
				continue;
			}

			if (c < ' ' || c >= 127 || c == '\\') {
				len += sprintf(user->buf + len, "\\x%02x", c);
				continue;
			}

			user->buf[len++] = c;
		}
		user->buf[len++] = '\n';
	}

	user->idx = log_next(user->idx);
	user->seq++;
	raw_spin_unlock_irq(&logbuf_lock);

	if (len > count) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(buf, user->buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	ret = len;
out:
	mutex_unlock(&user->lock);
	return ret;
}

static loff_t devkmsg_llseek(struct file *file, loff_t offset, int whence)
{
	struct devkmsg_user *user = file->private_data;
	loff_t ret = 0;

	if (!user)
		return -EBADF;
	if (offset)
		return -ESPIPE;

	raw_spin_lock_irq(&logbuf_lock);
	switch (whence) {
	case SEEK_SET:
		/* the first record */
		user->idx = log_first_idx;
		user->seq = log_first_seq;
		break;
	case SEEK_DATA:
		/*
		 * The first record after the last SYSLOG_ACTION_CLEAR,
		 * like issued by 'dmesg -c'. Reading /dev/kmsg itself
		 * changes no global state, and does not clear anything.
		 */
		user->idx = clear_idx;
		user->seq = clear_seq;
		break;
	case SEEK_END:
		/* after the last record */
		user->idx = log_next_idx;
		user->seq = log_next_seq;
		break;
	default:
		ret = -EINVAL;
	}
	raw_spin_unlock_irq(&logbuf_lock);
	return ret;
}

static unsigned int devkmsg_poll(struct file *file, poll_table *wait)
{
	struct devkmsg_user *user = file->private_data;
	int ret = 0;

	if (!user)
		return POLLERR|POLLNVAL;

	poll_wait(file, &log_wait, wait);

	raw_spin_lock_irq(&logbuf_lock);
	if (user->seq < log_next_seq) {
		/* return error when data has vanished underneath us */
		if (user->seq < log_first_seq)
			ret = POLLIN|POLLRDNORM|POLLERR|POLLPRI;
		else
			ret = POLLIN|POLLRDNORM;
	}
	raw_spin_unlock_irq(&logbuf_lock);

	return ret;
}

static int devkmsg_open(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user;
	int err;

	/* write-only does not need any file context */
	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		return 0;

	err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
				       SYSLOG_FROM_READER);
	if (err)
		return err;

	user = kmalloc(sizeof(struct devkmsg_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	mutex_init(&user->lock);

	raw_spin_lock_irq(&logbuf_lock);
	user->idx = log_first_idx;
	user->seq = log_first_seq;
	raw_spin_unlock_irq(&logbuf_lock);

	file->private_data = user;
	return 0;
}

static int devkmsg_release(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user = file->private_data;

	if (!user)
		return 0;

	mutex_destroy(&user->lock);
	kfree(user);
	return 0;
}

const struct file_operations kmsg_fops = {
	.open = devkmsg_open,
	.read = devkmsg_read,
	.write_iter = devkmsg_write,
	.llseek = devkmsg_llseek,
	.poll = devkmsg_poll,
	.release = devkmsg_release,
};

static void kdb_cmderror(int diag)
{
	int i;

	if (diag >= 0) {
		kdb_printf("no error detected (diagnostic is %d)\n", diag);
		return;
	}

	for (i = 0; i < __nkdb_err; i++) {
		if (kdbmsgs[i].km_diag == diag) {
			kdb_printf("diag: %d: %s\n", diag, kdbmsgs[i].km_msg);
			return;
		}
	}

	kdb_printf("Unknown diag %d\n", -diag);
}

/*
 * kdb_defcmd, kdb_defcmd2 - This function implements the 'defcmd'
 *	command which defines one command as a set of other commands,
 *	terminated by endefcmd.  kdb_defcmd processes the initial
 *	'defcmd' command, kdb_defcmd2 is invoked from kdb_parse for
 *	the following commands until 'endefcmd'.
 * Inputs:
 *	argc	argument count
 *	argv	argument vector
 * Returns:
 *	zero for success, a kdb diagnostic if error
 */
struct defcmd_set {
	int count;
	int usable;
	char *name;
	char *usage;
	char *help;
	char **command;
};
static struct defcmd_set *defcmd_set;
static int defcmd_set_count;
static int defcmd_in_progress;

/* Forward references */
static int kdb_exec_defcmd(int argc, const char **argv);

static int kdb_defcmd2(const char *cmdstr, const char *argv0)
{
	struct defcmd_set *s = defcmd_set + defcmd_set_count - 1;
	char **save_command = s->command;
	if (strcmp(argv0, "endefcmd") == 0) {
		defcmd_in_progress = 0;
		if (!s->count)
			s->usable = 0;
		if (s->usable)
			/* macros are always safe because when executed each
			 * internal command re-enters kdb_parse() and is
			 * safety checked individually.
			 */
			kdb_register_flags(s->name, kdb_exec_defcmd, s->usage,
					   s->help, 0,
					   KDB_ENABLE_ALWAYS_SAFE);
		return 0;
	}
	if (!s->usable)
		return KDB_NOTIMP;
	s->command = kzalloc((s->count + 1) * sizeof(*(s->command)), GFP_KDB);
	if (!s->command) {
		kdb_printf("Could not allocate new kdb_defcmd table for %s\n",
			   cmdstr);
		s->usable = 0;
		return KDB_NOTIMP;
	}
	memcpy(s->command, save_command, s->count * sizeof(*(s->command)));
	s->command[s->count++] = kdb_strdup(cmdstr, GFP_KDB);
	kfree(save_command);
	return 0;
}

static int kdb_defcmd(int argc, const char **argv)
{
	struct defcmd_set *save_defcmd_set = defcmd_set, *s;
	if (defcmd_in_progress) {
		kdb_printf("kdb: nested defcmd detected, assuming missing "
			   "endefcmd\n");
		kdb_defcmd2("endefcmd", "endefcmd");
	}
	if (argc == 0) {
		int i;
		for (s = defcmd_set; s < defcmd_set + defcmd_set_count; ++s) {
			kdb_printf("defcmd %s \"%s\" \"%s\"\n", s->name,
				   s->usage, s->help);
			for (i = 0; i < s->count; ++i)
				kdb_printf("%s", s->command[i]);
			kdb_printf("endefcmd\n");
		}
		return 0;
	}
	if (argc != 3)
		return KDB_ARGCOUNT;
	if (in_dbg_master()) {
		kdb_printf("Command only available during kdb_init()\n");
		return KDB_NOTIMP;
	}
	defcmd_set = kmalloc((defcmd_set_count + 1) * sizeof(*defcmd_set),
			     GFP_KDB);
	if (!defcmd_set)
		goto fail_defcmd;
	memcpy(defcmd_set, save_defcmd_set,
	       defcmd_set_count * sizeof(*defcmd_set));
	s = defcmd_set + defcmd_set_count;
	memset(s, 0, sizeof(*s));
	s->usable = 1;
	s->name = kdb_strdup(argv[1], GFP_KDB);
	if (!s->name)
		goto fail_name;
	s->usage = kdb_strdup(argv[2], GFP_KDB);
	if (!s->usage)
		goto fail_usage;
	s->help = kdb_strdup(argv[3], GFP_KDB);
	if (!s->help)
		goto fail_help;
	if (s->usage[0] == '"') {
		strcpy(s->usage, argv[2]+1);
		s->usage[strlen(s->usage)-1] = '\0';
	}
	if (s->help[0] == '"') {
		strcpy(s->help, argv[3]+1);
		s->help[strlen(s->help)-1] = '\0';
	}
	++defcmd_set_count;
	defcmd_in_progress = 1;
	kfree(save_defcmd_set);
	return 0;
fail_help:
	kfree(s->usage);
fail_usage:
	kfree(s->name);
fail_name:
	kfree(defcmd_set);
fail_defcmd:
	kdb_printf("Could not allocate new defcmd_set entry for %s\n", argv[1]);
	defcmd_set = save_defcmd_set;
	return KDB_NOTIMP;
}

/*
 * kdb_exec_defcmd - Execute the set of commands associated with this
 *	defcmd name.
 * Inputs:
 *	argc	argument count
 *	argv	argument vector
 * Returns:
 *	zero for success, a kdb diagnostic if error
 */
static int kdb_exec_defcmd(int argc, const char **argv)
{
	int i, ret;
	struct defcmd_set *s;
	if (argc != 0)
		return KDB_ARGCOUNT;
	for (s = defcmd_set, i = 0; i < defcmd_set_count; ++i, ++s) {
		if (strcmp(s->name, argv[0]) == 0)
			break;
	}
	if (i == defcmd_set_count) {
		kdb_printf("kdb_exec_defcmd: could not find commands for %s\n",
			   argv[0]);
		return KDB_NOTIMP;
	}
	for (i = 0; i < s->count; ++i) {
		/* Recursive use of kdb_parse, do not use argv after
		 * this point */
		argv = NULL;
		kdb_printf("[%s]kdb> %s\n", s->name, s->command[i]);
		ret = kdb_parse(s->command[i]);
		if (ret)
			return ret;
	}
	return 0;
}

/* Command history */
#define KDB_CMD_HISTORY_COUNT	32
#define CMD_BUFLEN		200	/* kdb_printf: max printline
					 * size == 256 */
static unsigned int cmd_head, cmd_tail;
static unsigned int cmdptr;
static char cmd_hist[KDB_CMD_HISTORY_COUNT][CMD_BUFLEN];
static char cmd_cur[CMD_BUFLEN];

#define EVENT_OWNER_KERNEL ((void *) -1)

static bool is_kernel_event(struct perf_event *event)
{
	return event->owner == EVENT_OWNER_KERNEL;
}

#define PERF_FLAG_ALL (PERF_FLAG_FD_NO_GROUP |\
		       PERF_FLAG_FD_OUTPUT  |\
		       PERF_FLAG_PID_CGROUP |\
		       PERF_FLAG_FD_CLOEXEC)

/*
 * branch priv levels that need permission checks
 */
#define PERF_SAMPLE_BRANCH_PERM_PLM \
	(PERF_SAMPLE_BRANCH_KERNEL |\
	 PERF_SAMPLE_BRANCH_HV)

#define DEFAULT_MAX_SAMPLE_RATE		100000
#define DEFAULT_SAMPLE_PERIOD_NS	(NSEC_PER_SEC / DEFAULT_MAX_SAMPLE_RATE)
#define DEFAULT_CPU_TIME_MAX_PERCENT	25



while (count_fls + sec_fls > 64 && nsec_fls + frequency_fls > 64) {
		REDUCE_FLS(nsec, frequency);
		REDUCE_FLS(sec, count);
	}

	if (count_fls + sec_fls > 64) {
		divisor = nsec * frequency;

		while (count_fls + sec_fls > 64) {
			REDUCE_FLS(count, sec);
			divisor >>= 1;
		}

		dividend = count * sec;
	} else {
		dividend = count * sec;

		while (nsec_fls + frequency_fls > 64) {
			REDUCE_FLS(nsec, frequency);
			dividend >>= 1;
		}

		divisor = nsec * frequency;
	}

	if (!divisor)
		return dividend;

	return div64_u64(dividend, divisor);
}

#define CLASSHASH_BITS		(MAX_LOCKDEP_KEYS_BITS - 1)
#define CLASSHASH_SIZE		(1UL << CLASSHASH_BITS)
#define __classhashfn(key)	hash_long((unsigned long)key, CLASSHASH_BITS)
#define classhashentry(key)	(classhash_table + __classhashfn((key)))

static struct list_head classhash_table[CLASSHASH_SIZE];

/*
 * We put the lock dependency chains into a hash-table as well, to cache
 * their existence:
 */
#define CHAINHASH_BITS		(MAX_LOCKDEP_CHAINS_BITS-1)
#define CHAINHASH_SIZE		(1UL << CHAINHASH_BITS)
#define __chainhashfn(chain)	hash_long(chain, CHAINHASH_BITS)
#define chainhashentry(chain)	(chainhash_table + __chainhashfn((chain)))

static struct list_head chainhash_table[CHAINHASH_SIZE];

/*
 * The hash key of the lock dependency chains is a hash itself too:
 * it's a hash of all locks taken up to that lock, including that lock.
 * It's a 64-bit hash, because it's important for the keys to be
 * unique.
 */
#define iterate_chain_key(key1, key2) \
	(((key1) << MAX_LOCKDEP_KEYS_BITS) ^ \
	((key1) >> (64-MAX_LOCKDEP_KEYS_BITS)) ^ \
	(key2))

void lockdep_off(void)
{
	current->lockdep_recursion++;
}
EXPORT_SYMBOL(lockdep_off);

void lockdep_on(void)
{
	current->lockdep_recursion--;
}
EXPORT_SYMBOL(lockdep_on);

/*
 * Debugging switches:
 */

#define VERBOSE			0
#define VERY_VERBOSE		0

#if VERBOSE
# define HARDIRQ_VERBOSE	1
# define SOFTIRQ_VERBOSE	1
# define RECLAIM_VERBOSE	1
#else
# define HARDIRQ_VERBOSE	0
# define SOFTIRQ_VERBOSE	0
# define RECLAIM_VERBOSE	0
#endif

#if VERBOSE || HARDIRQ_VERBOSE || SOFTIRQ_VERBOSE || RECLAIM_VERBOSE
/*
 * Quick filtering for interesting events:
 */
static int class_filter(struct lock_class *class)
{
#if 0
	/* Example */
	if (class->name_version == 1 &&
			!strcmp(class->name, "lockname"))
		return 1;
	if (class->name_version == 1 &&
			!strcmp(class->name, "&struct->lockfield"))
		return 1;
#endif
	/* Filter everything else. 1 would be to allow everything else */
	return 0;
}
#endif

static int verbose(struct lock_class *class)
{
#if VERBOSE
	return class_filter(class);
#endif
	return 0;
}

/*
 * Stack-trace: tightly packed array of stack backtrace
 * addresses. Protected by the graph_lock.
 */
unsigned long nr_stack_trace_entries;
static unsigned long stack_trace[MAX_STACK_TRACE_ENTRIES];

static void print_lockdep_off(const char *bug_msg)
{
	printk(KERN_DEBUG "%s\n", bug_msg);
	printk(KERN_DEBUG "turning off the locking correctness validator.\n");
#ifdef CONFIG_LOCK_STAT
	printk(KERN_DEBUG "Please attach the output of /proc/lock_stat to the bug report\n");
#endif
}

static int save_trace(struct stack_trace *trace)
{
	trace->nr_entries = 0;
	trace->max_entries = MAX_STACK_TRACE_ENTRIES - nr_stack_trace_entries;
	trace->entries = stack_trace + nr_stack_trace_entries;

	trace->skip = 3;

	save_stack_trace(trace);

	/*
	 * Some daft arches put -1 at the end to indicate its a full trace.
	 *
	 * <rant> this is buggy anyway, since it takes a whole extra entry so a
	 * complete trace that maxes out the entries provided will be reported
	 * as incomplete, friggin useless </rant>
	 */
	if (trace->nr_entries != 0 &&
	    trace->entries[trace->nr_entries-1] == ULONG_MAX)
		trace->nr_entries--;

	trace->max_entries = trace->nr_entries;

	nr_stack_trace_entries += trace->nr_entries;

	if (nr_stack_trace_entries >= MAX_STACK_TRACE_ENTRIES-1) {
		if (!debug_locks_off_graph_unlock())
			return 0;

		print_lockdep_off("BUG: MAX_STACK_TRACE_ENTRIES too low!");
		dump_stack();

		return 0;
	}

	return 1;
}

unsigned int nr_hardirq_chains;
unsigned int nr_softirq_chains;
unsigned int nr_process_chains;
unsigned int max_lockdep_depth;

#ifdef CONFIG_DEBUG_LOCKDEP
/*
 * We cannot printk in early bootup code. Not even early_printk()
 * might work. So we mark any initialization errors and printk
 * about it later on, in lockdep_info().
 */
static int lockdep_init_error;
static const char *lock_init_error;
static unsigned long lockdep_init_trace_data[20];
static struct stack_trace lockdep_init_trace = {
	.max_entries = ARRAY_SIZE(lockdep_init_trace_data),
	.entries = lockdep_init_trace_data,
};

/*
 * Various lockdep statistics:
 */
DEFINE_PER_CPU(struct lockdep_stats, lockdep_stats);
#endif

/*
 * Locking printouts:
 */


static const char *usage_str[] =
{
#define LOCKDEP_STATE(__STATE) __USAGE(__STATE)
#undef LOCKDEP_STATE
	[LOCK_USED] = "INITIAL USE",
};

const char * __get_key_name(struct lockdep_subclass_key *key, char *str)
{
	return kallsyms_lookup((unsigned long)key, NULL, NULL, NULL, str);
}

static inline unsigned long lock_flag(enum lock_usage_bit bit)
{
	return 1UL << bit;
}

static char get_usage_char(struct lock_class *class, enum lock_usage_bit bit)
{
	char c = '.';

	if (class->usage_mask & lock_flag(bit + 2))
		c = '+';
	if (class->usage_mask & lock_flag(bit)) {
		c = '-';
		if (class->usage_mask & lock_flag(bit + 2))
			c = '?';
	}

	return c;
}

void get_usage_chars(struct lock_class *class, char usage[LOCK_USAGE_CHARS])
{
	int i = 0;


static void __print_lock_name(struct lock_class *class)
{
	char str[KSYM_NAME_LEN];
	const char *name;

	name = class->name;
	if (!name) {
		name = __get_key_name(class->key, str);
		printk("%s", name);
	} else {
		printk("%s", name);
		if (class->name_version > 1)
			printk("#%d", class->name_version);
		if (class->subclass)
			printk("/%d", class->subclass);
	}
}

static void print_lock_name(struct lock_class *class)
{
	char usage[LOCK_USAGE_CHARS];

	get_usage_chars(class, usage);

	printk(" (");
	__print_lock_name(class);
	printk("){%s}", usage);
}

static void print_lockdep_cache(struct lockdep_map *lock)
{
	const char *name;
	char str[KSYM_NAME_LEN];

	name = lock->name;
	if (!name)
		name = __get_key_name(lock->key->subkeys, str);

	printk("%s", name);
}

static void print_lock(struct held_lock *hlock)
{
	print_lock_name(hlock_class(hlock));
	printk(", at: ");
	print_ip_sym(hlock->acquire_ip);
}

static void lockdep_print_held_locks(struct task_struct *curr)
{
	int i, depth = curr->lockdep_depth;

	if (!depth) {
		printk("no locks held by %s/%d.\n", curr->comm, task_pid_nr(curr));
		return;
	}
	printk("%d lock%s held by %s/%d:\n",
		depth, depth > 1 ? "s" : "", curr->comm, task_pid_nr(curr));

	for (i = 0; i < depth; i++) {
		printk(" #%d: ", i);
		print_lock(curr->held_locks + i);
	}
}

static void print_kernel_ident(void)
{
	printk("%s %.*s %s\n", init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version,
		print_tainted());
}

static int very_verbose(struct lock_class *class)
{
#if VERY_VERBOSE
	return class_filter(class);
#endif
	return 0;
}

/*
 * Is this the address of a static object:
 */
#ifdef __KERNEL__
static int static_obj(void *obj)
{
	unsigned long start = (unsigned long) &_stext,
		      end   = (unsigned long) &_end,
		      addr  = (unsigned long) obj;

	/*
	 * static variable?
	 */
	if ((addr >= start) && (addr < end))
		return 1;

	if (arch_is_kernel_data(addr))
		return 1;

	/*
	 * in-kernel percpu var?
	 */
	if (is_kernel_percpu_address(addr))
		return 1;

	/*
	 * module static or percpu var?
	 */
	return is_module_address(addr) || is_module_percpu_address(addr);
}
#endif

/*
 * To make lock name printouts unique, we calculate a unique
 * class->name_version generation counter:
 */
static int count_matching_names(struct lock_class *new_class)
{
	struct lock_class *class;
	int count = 0;

	if (!new_class->name)
		return 0;

	list_for_each_entry(class, &all_lock_classes, lock_entry) {
		if (new_class->key - new_class->subclass == class->key)
			return class->name_version;
		if (class->name && !strcmp(class->name, new_class->name))
			count = max(count, class->name_version);
	}

	return count + 1;
}

/*
 * Register a lock's class in the hash-table, if the class is not present
 * yet. Otherwise we look it up. We cache the result in the lock object
 * itself, so actual lookup of the hash should be once per lock object.
 */
static inline struct lock_class *
look_up_lock_class(struct lockdep_map *lock, unsigned int subclass)
{
	struct lockdep_subclass_key *key;
	struct list_head *hash_head;
	struct lock_class *class;

#ifdef CONFIG_DEBUG_LOCKDEP
	/*
	 * If the architecture calls into lockdep before initializing
	 * the hashes then we'll warn about it later. (we cannot printk
	 * right now)
	 */
	if (unlikely(!lockdep_initialized)) {
		lockdep_init();
		lockdep_init_error = 1;
		lock_init_error = lock->name;
		save_stack_trace(&lockdep_init_trace);
	}
#endif

	if (unlikely(subclass >= MAX_LOCKDEP_SUBCLASSES)) {
		debug_locks_off();
		printk(KERN_ERR
			"BUG: looking up invalid subclass: %u\n", subclass);
		printk(KERN_ERR
			"turning off the locking correctness validator.\n");
		dump_stack();
		return NULL;
	}

	/*
	 * Static locks do not have their class-keys yet - for them the key
	 * is the lock object itself:
	 */
	if (unlikely(!lock->key))
		lock->key = (void *)lock;

	/*
	 * NOTE: the class-key must be unique. For dynamic locks, a static
	 * lock_class_key variable is passed in through the mutex_init()
	 * (or spin_lock_init()) call - which acts as the key. For static
	 * locks we use the lock object itself as the key.
	 */
	BUILD_BUG_ON(sizeof(struct lock_class_key) >
			sizeof(struct lockdep_map));

	key = lock->key->subkeys + subclass;

	hash_head = classhashentry(key);

	/*
	 * We can walk the hash lockfree, because the hash only
	 * grows, and we are careful when adding entries to the end:
	 */
	list_for_each_entry(class, hash_head, hash_entry) {
		if (class->key == key) {
			/*
			 * Huh! same key, different name? Did someone trample
			 * on some memory? We're most confused.
			 */
			WARN_ON_ONCE(class->name != lock->name);
			return class;
		}
	}

	return NULL;
}




#undef SCHED_FEAT

#ifdef CONFIG_SCHED_DEBUG
#define SCHED_FEAT(name, enabled)	\
	#name ,

static const char * const sched_feat_names[] = {
};

#undef SCHED_FEAT

static int sched_feat_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < __SCHED_FEAT_NR; i++) {
		if (!(sysctl_sched_features & (1UL << i)))
			seq_puts(m, "NO_");
		seq_printf(m, "%s ", sched_feat_names[i]);
	}
	seq_puts(m, "\n");

	return 0;
}

#ifdef HAVE_JUMP_LABEL

#define jump_label_key__true  STATIC_KEY_INIT_TRUE
#define jump_label_key__false STATIC_KEY_INIT_FALSE


struct static_key sched_feat_keys[__SCHED_FEAT_NR] = {
};

#undef SCHED_FEAT

static void sched_feat_disable(int i)
{
	if (static_key_enabled(&sched_feat_keys[i]))
		static_key_slow_dec(&sched_feat_keys[i]);
}

static void sched_feat_enable(int i)
{
	if (!static_key_enabled(&sched_feat_keys[i]))
		static_key_slow_inc(&sched_feat_keys[i]);
}
#else
static void sched_feat_disable(int i) { };
static void sched_feat_enable(int i) { };
#endif /* HAVE_JUMP_LABEL */

static int sched_feat_set(char *cmp)
{
	int i;
	int neg = 0;

	if (strncmp(cmp, "NO_", 3) == 0) {
		neg = 1;
		cmp += 3;
	}

	for (i = 0; i < __SCHED_FEAT_NR; i++) {
		if (strcmp(cmp, sched_feat_names[i]) == 0) {
			if (neg) {
				sysctl_sched_features &= ~(1UL << i);
				sched_feat_disable(i);
			} else {
				sysctl_sched_features |= (1UL << i);
				sched_feat_enable(i);
			}
			break;
		}
	}

	return i;
}

static ssize_t
sched_feat_write(struct file *filp, const char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	char buf[64];
	char *cmp;
	int i;
	struct inode *inode;

	if (cnt > 63)
		cnt = 63;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;
	cmp = strstrip(buf);

	/* Ensure the static_key remains in a consistent state */
	inode = file_inode(filp);
	mutex_lock(&inode->i_mutex);
	i = sched_feat_set(cmp);
	mutex_unlock(&inode->i_mutex);
	if (i == __SCHED_FEAT_NR)
		return -EINVAL;

	*ppos += cnt;

	return cnt;
}

static int sched_feat_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_feat_show, NULL);
}

#define FTRACE_WARN_ON(cond)			\
	({					\
		int ___r = cond;		\
		if (WARN_ON(___r))		\
			ftrace_kill();		\
		___r;				\
	})

#define FTRACE_WARN_ON_ONCE(cond)		\
	({					\
		int ___r = cond;		\
		if (WARN_ON_ONCE(___r))		\
			ftrace_kill();		\
		___r;				\
	})

/* hash bits for specific function selection */
#define FTRACE_HASH_BITS 7
#define FTRACE_FUNC_HASHSIZE (1 << FTRACE_HASH_BITS)
#define FTRACE_HASH_DEFAULT_BITS 10
#define FTRACE_HASH_MAX_BITS 12

#define FL_GLOBAL_CONTROL_MASK (FTRACE_OPS_FL_CONTROL)

#ifdef CONFIG_DYNAMIC_FTRACE
#define INIT_OPS_HASH(opsname)	\
	.func_hash		= &opsname.local_hash,			\
	.local_hash.regex_lock	= __MUTEX_INITIALIZER(opsname.local_hash.regex_lock),
#define ASSIGN_OPS_HASH(opsname, val) \
	.func_hash		= val, \
	.local_hash.regex_lock	= __MUTEX_INITIALIZER(opsname.local_hash.regex_lock),
#else
#define INIT_OPS_HASH(opsname)
#define ASSIGN_OPS_HASH(opsname, val)
#endif

static struct ftrace_ops ftrace_list_end __read_mostly = {
	.func		= ftrace_stub,
	.flags		= FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_STUB,
	INIT_OPS_HASH(ftrace_list_end)
};

/* ftrace_enabled is a method to turn ftrace on or off */
int ftrace_enabled __read_mostly;
static int last_ftrace_enabled;

/* Current function tracing op */
struct ftrace_ops *function_trace_op __read_mostly = &ftrace_list_end;
/* What to set function_trace_op to */
static struct ftrace_ops *set_function_trace_op;

/* List for set_ftrace_pid's pids. */
LIST_HEAD(ftrace_pids);
struct ftrace_pid {
	struct list_head list;
	struct pid *pid;
};

/*
 * ftrace_disabled is set when an anomaly is discovered.
 * ftrace_disabled is much stronger than ftrace_enabled.
 */
static int ftrace_disabled __read_mostly;

static DEFINE_MUTEX(ftrace_lock);

static struct ftrace_ops *ftrace_control_list __read_mostly = &ftrace_list_end;
static struct ftrace_ops *ftrace_ops_list __read_mostly = &ftrace_list_end;
ftrace_func_t ftrace_trace_function __read_mostly = ftrace_stub;
ftrace_func_t ftrace_pid_function __read_mostly = ftrace_stub;
static struct ftrace_ops global_ops;
static struct ftrace_ops control_ops;

static void ftrace_ops_recurs_func(unsigned long ip, unsigned long parent_ip,
				   struct ftrace_ops *op, struct pt_regs *regs);

#if ARCH_SUPPORTS_FTRACE_OPS
static void ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
				 struct ftrace_ops *op, struct pt_regs *regs);
#else
/* See comment below, where ftrace_ops_list_func is defined */
static void ftrace_ops_no_ops(unsigned long ip, unsigned long parent_ip);
#define ftrace_ops_list_func ((ftrace_func_t)ftrace_ops_no_ops)
#endif

/*
 * Traverse the ftrace_global_list, invoking all entries.  The reason that we
 * can use rcu_dereference_raw_notrace() is that elements removed from this list
 * are simply leaked, so there is no need to interact with a grace-period
 * mechanism.  The rcu_dereference_raw_notrace() calls are needed to handle
 * concurrent insertions into the ftrace_global_list.
 *
 * Silly Alpha and silly pointer-speculation compiler optimizations!
 */
#define do_for_each_ftrace_op(op, list)			\
	op = rcu_dereference_raw_notrace(list);			\
	do

/*
 * Optimized for just a single item in the list (as that is the normal case).
 */
#define while_for_each_ftrace_op(op)				\
	while (likely(op = rcu_dereference_raw_notrace((op)->next)) &&	\
	       unlikely((op) != &ftrace_list_end))

static inline void ftrace_ops_init(struct ftrace_ops *ops)
{
#ifdef CONFIG_DYNAMIC_FTRACE
	if (!(ops->flags & FTRACE_OPS_FL_INITIALIZED)) {
		mutex_init(&ops->local_hash.regex_lock);
		ops->func_hash = &ops->local_hash;
		ops->flags |= FTRACE_OPS_FL_INITIALIZED;
	}
#endif
}

/**
 * ftrace_nr_registered_ops - return number of ops registered
 *
 * Returns the number of ftrace_ops registered and tracing functions
 */
int ftrace_nr_registered_ops(void)
{
	struct ftrace_ops *ops;
	int cnt = 0;

	mutex_lock(&ftrace_lock);

	for (ops = ftrace_ops_list;
	     ops != &ftrace_list_end; ops = ops->next)
		cnt++;

	mutex_unlock(&ftrace_lock);

	return cnt;
}

static void ftrace_pid_func(unsigned long ip, unsigned long parent_ip,
			    struct ftrace_ops *op, struct pt_regs *regs)
{
	if (!test_tsk_trace_trace(current))
		return;

	ftrace_pid_function(ip, parent_ip, op, regs);
}

static void set_ftrace_pid_function(ftrace_func_t func)
{
	/* do not set ftrace_pid_function to itself! */
	if (func != ftrace_pid_func)
		ftrace_pid_function = func;
}

/**
 * clear_ftrace_function - reset the ftrace function
 *
 * This NULLs the ftrace function and in essence stops
 * tracing.  There may be lag
 */
void clear_ftrace_function(void)
{
	ftrace_trace_function = ftrace_stub;
	ftrace_pid_function = ftrace_stub;
}

static void control_ops_disable_all(struct ftrace_ops *ops)
{
	int cpu;

	for_each_possible_cpu(cpu)
		*per_cpu_ptr(ops->disabled, cpu) = 1;
}

static int control_ops_alloc(struct ftrace_ops *ops)
{
	int __percpu *disabled;

	disabled = alloc_percpu(int);
	if (!disabled)
		return -ENOMEM;

	ops->disabled = disabled;
	control_ops_disable_all(ops);
	return 0;
}

static void ftrace_sync(struct work_struct *work)
{
	/*
	 * This function is just a stub to implement a hard force
	 * of synchronize_sched(). This requires synchronizing
	 * tasks even in userspace and idle.
	 *
	 * Yes, function tracing is rude.
	 */
}

static void ftrace_sync_ipi(void *data)
{
	/* Probably not needed, but do it anyway */
	smp_rmb();
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
static void update_function_graph_func(void);
#else
static inline void update_function_graph_func(void) { }
#endif

static void update_ftrace_function(void)
{
	ftrace_func_t func;

	/*
	 * Prepare the ftrace_ops that the arch callback will use.
	 * If there's only one ftrace_ops registered, the ftrace_ops_list
	 * will point to the ops we want.
	 */
	set_function_trace_op = ftrace_ops_list;

	/* If there's no ftrace_ops registered, just call the stub function */
	if (ftrace_ops_list == &ftrace_list_end) {
		func = ftrace_stub;

	/*
	 * If we are at the end of the list and this ops is
	 * recursion safe and not dynamic and the arch supports passing ops,
	 * then have the mcount trampoline call the function directly.
	 */
	} else if (ftrace_ops_list->next == &ftrace_list_end) {
		func = ftrace_ops_get_func(ftrace_ops_list);

	} else {
		/* Just use the default ftrace_ops */
		set_function_trace_op = &ftrace_list_end;
		func = ftrace_ops_list_func;
	}

	update_function_graph_func();

	/* If there's no change, then do nothing more here */
	if (ftrace_trace_function == func)
		return;

	/*
	 * If we are using the list function, it doesn't care
	 * about the function_trace_ops.
	 */
	if (func == ftrace_ops_list_func) {
		ftrace_trace_function = func;
		/*
		 * Don't even bother setting function_trace_ops,
		 * it would be racy to do so anyway.
		 */
		return;
	}

#define do_for_each_ftrace_rec(pg, rec)					\
	for (pg = ftrace_pages_start; pg; pg = pg->next) {		\
		int _____i;						\
		for (_____i = 0; _____i < pg->index; _____i++) {	\
			rec = &pg->records[_____i];

#define while_for_each_ftrace_rec()		\
		}				\
	}


static int ftrace_cmp_recs(const void *a, const void *b)
{
	const struct dyn_ftrace *key = a;
	const struct dyn_ftrace *rec = b;

	if (key->flags < rec->ip)
		return -1;
	if (key->ip >= rec->ip + MCOUNT_INSN_SIZE)
		return 1;
	return 0;
}

static unsigned long ftrace_location_range(unsigned long start, unsigned long end)
{
	struct ftrace_page *pg;
	struct dyn_ftrace *rec;
	struct dyn_ftrace key;

	key.ip = start;
	key.flags = end;	/* overload flags, as it is unsigned long */

	for (pg = ftrace_pages_start; pg; pg = pg->next) {
		if (end < pg->records[0].ip ||
		    start >= (pg->records[pg->index - 1].ip + MCOUNT_INSN_SIZE))
			continue;
		rec = bsearch(&key, pg->records, pg->index,
			      sizeof(struct dyn_ftrace),
			      ftrace_cmp_recs);
		if (rec)
			return rec->ip;
	}

	return 0;
}

/**
 * ftrace_location - return true if the ip giving is a traced location
 * @ip: the instruction pointer to check
 *
 * Returns rec->ip if @ip given is a pointer to a ftrace location.
 * That is, the instruction that is either a NOP or call to
 * the function tracer. It checks the ftrace internal tables to
 * determine if the address belongs or not.
 */
unsigned long ftrace_location(unsigned long ip)
{
	return ftrace_location_range(ip, ip);
}

/**
 * ftrace_text_reserved - return true if range contains an ftrace location
 * @start: start of range to search
 * @end: end of range to search (inclusive). @end points to the last byte to check.
 *
 * Returns 1 if @start and @end contains a ftrace location.
 * That is, the instruction that is either a NOP or call to
 * the function tracer. It checks the ftrace internal tables to
 * determine if the address belongs or not.
 */
int ftrace_text_reserved(const void *start, const void *end)
{
	unsigned long ret;

	ret = ftrace_location_range((unsigned long)start,
				    (unsigned long)end);

	return (int)!!ret;
}

/* Test if ops registered to this rec needs regs */
static bool test_rec_ops_needs_regs(struct dyn_ftrace *rec)
{
	struct ftrace_ops *ops;
	bool keep_regs = false;

	for (ops = ftrace_ops_list;
	     ops != &ftrace_list_end; ops = ops->next) {
		/* pass rec in as regs to have non-NULL val */
		if (ftrace_ops_test(ops, rec->ip, rec)) {
			if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
				keep_regs = true;
				break;
			}
		}
	}

	return  keep_regs;
}

static void __ftrace_hash_rec_update(struct ftrace_ops *ops,
				     int filter_hash,
				     bool inc)
{
	struct ftrace_hash *hash;
	struct ftrace_hash *other_hash;
	struct ftrace_page *pg;
	struct dyn_ftrace *rec;
	int count = 0;
	int all = 0;

	/* Only update if the ops has been registered */
	if (!(ops->flags & FTRACE_OPS_FL_ENABLED))
		return;

	/*
	 * In the filter_hash case:
	 *   If the count is zero, we update all records.
	 *   Otherwise we just update the items in the hash.
	 *
	 * In the notrace_hash case:
	 *   We enable the update in the hash.
	 *   As disabling notrace means enabling the tracing,
	 *   and enabling notrace means disabling, the inc variable
	 *   gets inversed.
	 */
	if (filter_hash) {
		hash = ops->func_hash->filter_hash;
		other_hash = ops->func_hash->notrace_hash;
		if (ftrace_hash_empty(hash))
			all = 1;
	} else {
		inc = !inc;
		hash = ops->func_hash->notrace_hash;
		other_hash = ops->func_hash->filter_hash;
		/*
		 * If the notrace hash has no items,
		 * then there's nothing to do.
		 */
		if (ftrace_hash_empty(hash))
			return;
	}

	do_for_each_ftrace_rec(pg, rec) {
		int in_other_hash = 0;
		int in_hash = 0;
		int match = 0;

		if (all) {
			/*
			 * Only the filter_hash affects all records.
			 * Update if the record is not in the notrace hash.
			 */
			if (!other_hash || !ftrace_lookup_ip(other_hash, rec->ip))
				match = 1;
		} else {
			in_hash = !!ftrace_lookup_ip(hash, rec->ip);
			in_other_hash = !!ftrace_lookup_ip(other_hash, rec->ip);

			/*
			 * If filter_hash is set, we want to match all functions
			 * that are in the hash but not in the other hash.
			 *
			 * If filter_hash is not set, then we are decrementing.
			 * That means we match anything that is in the hash
			 * and also in the other_hash. That is, we need to turn
			 * off functions in the other hash because they are disabled
			 * by this hash.
			 */
			if (filter_hash && in_hash && !in_other_hash)
				match = 1;
			else if (!filter_hash && in_hash &&
				 (in_other_hash || ftrace_hash_empty(other_hash)))
				match = 1;
		}
		if (!match)
			continue;

		if (inc) {
			rec->flags++;
			if (FTRACE_WARN_ON(ftrace_rec_count(rec) == FTRACE_REF_MAX))
				return;

			/*
			 * If there's only a single callback registered to a
			 * function, and the ops has a trampoline registered
			 * for it, then we can call it directly.
			 */
			if (ftrace_rec_count(rec) == 1 && ops->trampoline)
				rec->flags |= FTRACE_FL_TRAMP;
			else
				/*
				 * If we are adding another function callback
				 * to this function, and the previous had a
				 * custom trampoline in use, then we need to go
				 * back to the default trampoline.
				 */
				rec->flags &= ~FTRACE_FL_TRAMP;

			/*
			 * If any ops wants regs saved for this function
			 * then all ops will get saved regs.
			 */
			if (ops->flags & FTRACE_OPS_FL_SAVE_REGS)
				rec->flags |= FTRACE_FL_REGS;
		} else {
			if (FTRACE_WARN_ON(ftrace_rec_count(rec) == 0))
				return;
			rec->flags--;

			/*
			 * If the rec had REGS enabled and the ops that is
			 * being removed had REGS set, then see if there is
			 * still any ops for this record that wants regs.
			 * If not, we can stop recording them.
			 */
			if (ftrace_rec_count(rec) > 0 &&
			    rec->flags & FTRACE_FL_REGS &&
			    ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
				if (!test_rec_ops_needs_regs(rec))
					rec->flags &= ~FTRACE_FL_REGS;
			}

			/*
			 * If the rec had TRAMP enabled, then it needs to
			 * be cleared. As TRAMP can only be enabled iff
			 * there is only a single ops attached to it.
			 * In otherwords, always disable it on decrementing.
			 * In the future, we may set it if rec count is
			 * decremented to one, and the ops that is left
			 * has a trampoline.
			 */
			rec->flags &= ~FTRACE_FL_TRAMP;

			/*
			 * flags will be cleared in ftrace_check_record()
			 * if rec count is zero.
			 */
		}
		count++;
		/* Shortcut, if we handled all records, we are done. */
		if (!all && count == hash->count)
			return;
	} while_for_each_ftrace_rec();
}

static void ftrace_hash_rec_disable(struct ftrace_ops *ops,
				    int filter_hash)
{
	__ftrace_hash_rec_update(ops, filter_hash, 0);
}

static void ftrace_hash_rec_enable(struct ftrace_ops *ops,
				   int filter_hash)
{
	__ftrace_hash_rec_update(ops, filter_hash, 1);
}

static void ftrace_hash_rec_update_modify(struct ftrace_ops *ops,
					  int filter_hash, int inc)
{
	struct ftrace_ops *op;

	__ftrace_hash_rec_update(ops, filter_hash, inc);

	if (ops->func_hash != &global_ops.local_hash)
		return;

	/*
	 * If the ops shares the global_ops hash, then we need to update
	 * all ops that are enabled and use this hash.
	 */
	do_for_each_ftrace_op(op, ftrace_ops_list) {
		/* Already done */
		if (op == ops)
			continue;
		if (op->func_hash == &global_ops.local_hash)
			__ftrace_hash_rec_update(op, filter_hash, inc);
	} while_for_each_ftrace_op(op);
}

static void ftrace_hash_rec_disable_modify(struct ftrace_ops *ops,
					   int filter_hash)
{
	ftrace_hash_rec_update_modify(ops, filter_hash, 0);
}

static void ftrace_hash_rec_enable_modify(struct ftrace_ops *ops,
					  int filter_hash)
{
	ftrace_hash_rec_update_modify(ops, filter_hash, 1);
}

/*
 * Try to update IPMODIFY flag on each ftrace_rec. Return 0 if it is OK
 * or no-needed to update, -EBUSY if it detects a conflict of the flag
 * on a ftrace_rec, and -EINVAL if the new_hash tries to trace all recs.
 * Note that old_hash and new_hash has below meanings
 *  - If the hash is NULL, it hits all recs (if IPMODIFY is set, this is rejected)
 *  - If the hash is EMPTY_HASH, it hits nothing
 *  - Anything else hits the recs which match the hash entries.
 */
static int __ftrace_hash_update_ipmodify(struct ftrace_ops *ops,
					 struct ftrace_hash *old_hash,
					 struct ftrace_hash *new_hash)
{
	struct ftrace_page *pg;
	struct dyn_ftrace *rec, *end = NULL;
	int in_old, in_new;

	/* Only update if the ops has been registered */
	if (!(ops->flags & FTRACE_OPS_FL_ENABLED))
		return 0;

	if (!(ops->flags & FTRACE_OPS_FL_IPMODIFY))
		return 0;

	/*
	 * Since the IPMODIFY is a very address sensitive action, we do not
	 * allow ftrace_ops to set all functions to new hash.
	 */
	if (!new_hash || !old_hash)
		return -EINVAL;

	/* Update rec->flags */
	do_for_each_ftrace_rec(pg, rec) {
		/* We need to update only differences of filter_hash */
		in_old = !!ftrace_lookup_ip(old_hash, rec->ip);
		in_new = !!ftrace_lookup_ip(new_hash, rec->ip);
		if (in_old == in_new)
			continue;

		if (in_new) {
			/* New entries must ensure no others are using it */
			if (rec->flags & FTRACE_FL_IPMODIFY)
				goto rollback;
			rec->flags |= FTRACE_FL_IPMODIFY;
		} else /* Removed entry */
			rec->flags &= ~FTRACE_FL_IPMODIFY;
	} while_for_each_ftrace_rec();

	return 0;

rollback:
	end = rec;

	/* Roll back what we did above */
	do_for_each_ftrace_rec(pg, rec) {
		if (rec == end)
			goto err_out;

		in_old = !!ftrace_lookup_ip(old_hash, rec->ip);
		in_new = !!ftrace_lookup_ip(new_hash, rec->ip);
		if (in_old == in_new)
			continue;

		if (in_new)
			rec->flags &= ~FTRACE_FL_IPMODIFY;
		else
			rec->flags |= FTRACE_FL_IPMODIFY;
	} while_for_each_ftrace_rec();

err_out:
	return -EBUSY;
}

#define do_for_each_event_file(tr, file)			\
	list_for_each_entry(tr, &ftrace_trace_arrays, list) {	\
		list_for_each_entry(file, &tr->events, list)

#define do_for_each_event_file_safe(tr, file)			\
	list_for_each_entry(tr, &ftrace_trace_arrays, list) {	\
		struct ftrace_event_file *___n;				\
		list_for_each_entry_safe(file, ___n, &tr->events, list)

#define while_for_each_event_file()		\
	}

static struct list_head *
trace_get_fields(struct ftrace_event_call *event_call)
{
	if (!event_call->class->get_fields)
		return &event_call->class->fields;
	return event_call->class->get_fields(event_call);
}

static struct ftrace_event_field *
__find_event_field(struct list_head *head, char *name)
{
	struct ftrace_event_field *field;

	list_for_each_entry(field, head, link) {
		if (!strcmp(field->name, name))
			return field;
	}

	return NULL;
}

struct ftrace_event_field *
trace_find_event_field(struct ftrace_event_call *call, char *name)
{
	struct ftrace_event_field *field;
	struct list_head *head;

	field = __find_event_field(&ftrace_common_fields, name);
	if (field)
		return field;

	head = trace_get_fields(call);
	return __find_event_field(head, name);
}

static int __trace_define_field(struct list_head *head, const char *type,
				const char *name, int offset, int size,
				int is_signed, int filter_type)
{
	struct ftrace_event_field *field;

	field = kmem_cache_alloc(field_cachep, GFP_TRACE);
	if (!field)
		return -ENOMEM;

	field->name = name;
	field->type = type;

	if (filter_type == FILTER_OTHER)
		field->filter_type = filter_assign_type(type);
	else
		field->filter_type = filter_type;

	field->offset = offset;
	field->size = size;
	field->is_signed = is_signed;

	list_add(&field->link, head);

	return 0;
}

int trace_define_field(struct ftrace_event_call *call, const char *type,
		       const char *name, int offset, int size, int is_signed,
		       int filter_type)
{
	struct list_head *head;

	if (WARN_ON(!call->class))
		return 0;

	head = trace_get_fields(call);
	return __trace_define_field(head, type, name, offset, size,
				    is_signed, filter_type);
}
EXPORT_SYMBOL_GPL(trace_define_field);

#define __common_field(type, item)					\
	ret = __trace_define_field(&ftrace_common_fields, #type,	\
				   "common_" #item,			\
				   offsetof(typeof(ent), item),		\
				   sizeof(ent.item),			\
				   is_signed_type(type), FILTER_OTHER);	\
	if (ret)							\
		return ret;

static int trace_define_common_fields(void)
{
	int ret;
	struct trace_entry ent;

	__common_field(unsigned short, type);
	__common_field(unsigned char, flags);
	__common_field(unsigned char, preempt_count);
	__common_field(int, pid);

	return ret;
}

static void trace_destroy_fields(struct ftrace_event_call *call)
{
	struct ftrace_event_field *field, *next;
	struct list_head *head;

	head = trace_get_fields(call);
	list_for_each_entry_safe(field, next, head, link) {
		list_del(&field->link);
		kmem_cache_free(field_cachep, field);
	}
}

int trace_event_raw_init(struct ftrace_event_call *call)
{
	int id;

	id = register_ftrace_event(&call->event);
	if (!id)
		return -ENODEV;

	return 0;
}
EXPORT_SYMBOL_GPL(trace_event_raw_init);

void *ftrace_event_buffer_reserve(struct ftrace_event_buffer *fbuffer,
				  struct ftrace_event_file *ftrace_file,
				  unsigned long len)
{
	struct ftrace_event_call *event_call = ftrace_file->event_call;

	local_save_flags(fbuffer->flags);
	fbuffer->pc = preempt_count();
	fbuffer->ftrace_file = ftrace_file;

	fbuffer->event =
		trace_event_buffer_lock_reserve(&fbuffer->buffer, ftrace_file,
						event_call->event.type, len,
						fbuffer->flags, fbuffer->pc);
	if (!fbuffer->event)
		return NULL;

	fbuffer->entry = ring_buffer_event_data(fbuffer->event);
	return fbuffer->entry;
}
EXPORT_SYMBOL_GPL(ftrace_event_buffer_reserve);

static DEFINE_SPINLOCK(tracepoint_iter_lock);

static void output_printk(struct ftrace_event_buffer *fbuffer)
{
	struct ftrace_event_call *event_call;
	struct trace_event *event;
	unsigned long flags;
	struct trace_iterator *iter = tracepoint_print_iter;

	if (!iter)
		return;

	event_call = fbuffer->ftrace_file->event_call;
	if (!event_call || !event_call->event.funcs ||
	    !event_call->event.funcs->trace)
		return;

	event = &fbuffer->ftrace_file->event_call->event;

	spin_lock_irqsave(&tracepoint_iter_lock, flags);
	trace_seq_init(&iter->seq);
	iter->ent = fbuffer->entry;
	event_call->event.funcs->trace(iter, 0, event);
	trace_seq_putc(&iter->seq, 0);
	printk("%s", iter->seq.buffer);

	spin_unlock_irqrestore(&tracepoint_iter_lock, flags);
}

void ftrace_event_buffer_commit(struct ftrace_event_buffer *fbuffer)
{
	if (tracepoint_printk)
		output_printk(fbuffer);

	event_trigger_unlock_commit(fbuffer->ftrace_file, fbuffer->buffer,
				    fbuffer->event, fbuffer->entry,
				    fbuffer->flags, fbuffer->pc);
}
EXPORT_SYMBOL_GPL(ftrace_event_buffer_commit);

int ftrace_event_reg(struct ftrace_event_call *call,
		     enum trace_reg type, void *data)
{
	struct ftrace_event_file *file = data;

	WARN_ON(!(call->flags & TRACE_EVENT_FL_TRACEPOINT));
	switch (type) {
	case TRACE_REG_REGISTER:
		return tracepoint_probe_register(call->tp,
						 call->class->probe,
						 file);
	case TRACE_REG_UNREGISTER:
		tracepoint_probe_unregister(call->tp,
					    call->class->probe,
					    file);
		return 0;

#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
		return tracepoint_probe_register(call->tp,
						 call->class->perf_probe,
						 call);
	case TRACE_REG_PERF_UNREGISTER:
		tracepoint_probe_unregister(call->tp,
					    call->class->perf_probe,
					    call);
		return 0;
	case TRACE_REG_PERF_OPEN:
	case TRACE_REG_PERF_CLOSE:
	case TRACE_REG_PERF_ADD:
	case TRACE_REG_PERF_DEL:
		return 0;
#endif
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ftrace_event_reg);

void trace_event_enable_cmd_record(bool enable)
{
	struct ftrace_event_file *file;
	struct trace_array *tr;

	mutex_lock(&event_mutex);
	do_for_each_event_file(tr, file) {

		if (!(file->flags & FTRACE_EVENT_FL_ENABLED))
			continue;

		if (enable) {
			tracing_start_cmdline_record();
			set_bit(FTRACE_EVENT_FL_RECORDED_CMD_BIT, &file->flags);
		} else {
			tracing_stop_cmdline_record();
			clear_bit(FTRACE_EVENT_FL_RECORDED_CMD_BIT, &file->flags);
		}
	} while_for_each_event_file();
	mutex_unlock(&event_mutex);
}

static const struct file_operations sched_feat_fops = {
	.open		= sched_feat_open,
	.write		= sched_feat_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static __init int sched_init_debug(void)
{
	debugfs_create_file("sched_features", 0644, NULL, NULL,
			&sched_feat_fops);

	return 0;
}
late_initcall(sched_init_debug);
#endif /* CONFIG_SCHED_DEBUG */

/*
 * Number of tasks to iterate in a single balance run.
 * Limited because this is done with IRQs disabled.
 */
const_debug unsigned int sysctl_sched_nr_migrate = 32;

/*
 * period over which we average the RT time consumption, measured
 * in ms.
 *
 * default: 1s
 */
const_debug unsigned int sysctl_sched_time_avg = MSEC_PER_SEC;

/*
 * period over which we measure -rt task cpu usage in us.
 * default: 1s
 */
unsigned int sysctl_sched_rt_period = 1000000;

__read_mostly int scheduler_running;

/*
 * part of the period that we allow rt tasks to run in us.
 * default: 0.95s
 */
int sysctl_sched_rt_runtime = 950000;

/*
 * __task_rq_lock - lock the rq @p resides on.
 */
static inline struct rq *__task_rq_lock(struct task_struct *p)
	__acquires(rq->lock)
{
	struct rq *rq;

	lockdep_assert_held(&p->pi_lock);

	for (;;) {
		rq = task_rq(p);
		raw_spin_lock(&rq->lock);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p)))
			return rq;
		raw_spin_unlock(&rq->lock);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

/*
 * task_rq_lock - lock p->pi_lock and lock the rq @p resides on.
 */
static struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
	__acquires(p->pi_lock)
	__acquires(rq->lock)
{
	struct rq *rq;

	for (;;) {
		raw_spin_lock_irqsave(&p->pi_lock, *flags);
		rq = task_rq(p);
		raw_spin_lock(&rq->lock);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p)))
			return rq;
		raw_spin_unlock(&rq->lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, *flags);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

static void __task_rq_unlock(struct rq *rq)
	__releases(rq->lock)
{
	raw_spin_unlock(&rq->lock);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	raw_spin_unlock(&rq->lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, *flags);
}

/*
 * this_rq_lock - lock this runqueue and disable interrupts.
 */
static struct rq *this_rq_lock(void)
	__acquires(rq->lock)
{
	struct rq *rq;

	local_irq_disable();
	rq = this_rq();
	raw_spin_lock(&rq->lock);

	return rq;
}

#ifdef CONFIG_SCHED_HRTICK
/*
 * Use HR-timers to deliver accurate preemption points.
 */

static void hrtick_clear(struct rq *rq)
{
	if (hrtimer_active(&rq->hrtick_timer))
		hrtimer_cancel(&rq->hrtick_timer);
}

/*
 * High-resolution timer tick.
 * Runs from hardirq context with interrupts disabled.
 */
static enum hrtimer_restart hrtick(struct hrtimer *timer)
{
	struct rq *rq = container_of(timer, struct rq, hrtick_timer);

	WARN_ON_ONCE(cpu_of(rq) != smp_processor_id());

	raw_spin_lock(&rq->lock);
	update_rq_clock(rq);
	rq->curr->sched_class->task_tick(rq, rq->curr, 1);
	raw_spin_unlock(&rq->lock);

	return HRTIMER_NORESTART;
}

#ifdef CONFIG_SMP

static int __hrtick_restart(struct rq *rq)
{
	struct hrtimer *timer = &rq->hrtick_timer;
	ktime_t time = hrtimer_get_softexpires(timer);

	return __hrtimer_start_range_ns(timer, time, 0, HRTIMER_MODE_ABS_PINNED, 0);
}

/*
 * called from hardirq (IPI) context
 */
static void __hrtick_start(void *arg)
{
	struct rq *rq = arg;

	raw_spin_lock(&rq->lock);
	__hrtick_restart(rq);
	rq->hrtick_csd_pending = 0;
	raw_spin_unlock(&rq->lock);
}

/*
 * Called to set the hrtick timer state.
 *
 * called with rq->lock held and irqs disabled
 */
void hrtick_start(struct rq *rq, u64 delay)
{
	struct hrtimer *timer = &rq->hrtick_timer;
	ktime_t time;
	s64 delta;

	/*
	 * Don't schedule slices shorter than 10000ns, that just
	 * doesn't make sense and can cause timer DoS.
	 */
	delta = max_t(s64, delay, 10000LL);
	time = ktime_add_ns(timer->base->get_time(), delta);

	hrtimer_set_expires(timer, time);

	if (rq == this_rq()) {
		__hrtick_restart(rq);
	} else if (!rq->hrtick_csd_pending) {
		smp_call_function_single_async(cpu_of(rq), &rq->hrtick_csd);
		rq->hrtick_csd_pending = 1;
	}
}

static int
hotplug_hrtick(struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	int cpu = (int)(long)hcpu;

	switch (action) {
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DOWN_PREPARE:
	case CPU_DOWN_PREPARE_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		hrtick_clear(cpu_rq(cpu));
		return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static __init void init_hrtick(void)
{
	hotcpu_notifier(hotplug_hrtick, 0);
}
#else
/*
 * Called to set the hrtick timer state.
 *
 * called with rq->lock held and irqs disabled
 */
void hrtick_start(struct rq *rq, u64 delay)
{
	__hrtimer_start_range_ns(&rq->hrtick_timer, ns_to_ktime(delay), 0,
			HRTIMER_MODE_REL_PINNED, 0);
}

static inline void init_hrtick(void)
{
}
#endif /* CONFIG_SMP */

static void init_rq_hrtick(struct rq *rq)
{
#ifdef CONFIG_SMP
	rq->hrtick_csd_pending = 0;

	rq->hrtick_csd.flags = 0;
	rq->hrtick_csd.func = __hrtick_start;
	rq->hrtick_csd.info = rq;
#endif

	hrtimer_init(&rq->hrtick_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rq->hrtick_timer.function = hrtick;
}
#else	/* CONFIG_SCHED_HRTICK */
static inline void hrtick_clear(struct rq *rq)
{
}

static inline void init_rq_hrtick(struct rq *rq)
{
}

static inline void init_hrtick(void)
{
}
#endif	/* CONFIG_SCHED_HRTICK */

/*
 * cmpxchg based fetch_or, macro so it works for different integer types
 */
#define fetch_or(ptr, val)						\
({	typeof(*(ptr)) __old, __val = *(ptr);				\
 	for (;;) {							\
 		__old = cmpxchg((ptr), __val, __val | (val));		\
 		if (__old == __val)					\
 			break;						\
 		__val = __old;						\
 	}								\
 	__old;								\
})

#if defined(CONFIG_SMP) && defined(TIF_POLLING_NRFLAG)
/*
 * Atomically set TIF_NEED_RESCHED and test for TIF_POLLING_NRFLAG,
 * this avoids any races wrt polling state changes and thereby avoids
 * spurious IPIs.
 */
static bool set_nr_and_not_polling(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);
	return !(fetch_or(&ti->flags, _TIF_NEED_RESCHED) & _TIF_POLLING_NRFLAG);
}

/*
 * Atomically set TIF_NEED_RESCHED if TIF_POLLING_NRFLAG is set.
 *
 * If this returns true, then the idle task promises to call
 * sched_ttwu_pending() and reschedule soon.
 */
static bool set_nr_if_polling(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);
	typeof(ti->flags) old, val = ACCESS_ONCE(ti->flags);

	for (;;) {
		if (!(val & _TIF_POLLING_NRFLAG))
			return false;
		if (val & _TIF_NEED_RESCHED)
			return true;
		old = cmpxchg(&ti->flags, val, val | _TIF_NEED_RESCHED);
		if (old == val)
			break;
		val = old;
	}
	return true;
}

#else
static bool set_nr_and_not_polling(struct task_struct *p)
{
	set_tsk_need_resched(p);
	return true;
}

#ifdef CONFIG_SMP
static bool set_nr_if_polling(struct task_struct *p)
{
	return false;
}
#endif
#endif

/*
 * resched_curr - mark rq's current task 'to be rescheduled now'.
 *
 * On UP this means the setting of the need_resched flag, on SMP it
 * might also involve a cross-CPU call to trigger the scheduler on
 * the target CPU.
 */
void resched_curr(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	int cpu;

	lockdep_assert_held(&rq->lock);

	if (test_tsk_need_resched(curr))
		return;

	cpu = cpu_of(rq);

	if (cpu == smp_processor_id()) {
		set_tsk_need_resched(curr);
		set_preempt_need_resched();
		return;
	}

	if (set_nr_and_not_polling(curr))
		smp_send_reschedule(cpu);
	else
		trace_sched_wake_idle_without_ipi(cpu);
}

#define for_each_sd_topology(tl)			\
	for (tl = sched_domain_topology; tl->mask; tl++)

void set_sched_topology(struct sched_domain_topology_level *tl)
{
	sched_domain_topology = tl;
}

#ifdef CONFIG_NUMA

static const struct cpumask *sd_numa_mask(int cpu)
{
	return sched_domains_numa_masks[sched_domains_curr_level][cpu_to_node(cpu)];
}

static void sched_numa_warn(const char *str)
{
	static int done = false;
	int i,j;

	if (done)
		return;

	done = true;

	printk(KERN_WARNING "ERROR: %s\n\n", str);

	for (i = 0; i < nr_node_ids; i++) {
		printk(KERN_WARNING "  ");
		for (j = 0; j < nr_node_ids; j++)
			printk(KERN_CONT "%02d ", node_distance(i,j));
		printk(KERN_CONT "\n");
	}
	printk(KERN_WARNING "\n");
}

bool find_numa_distance(int distance)
{
	int i;

	if (distance == node_distance(0, 0))
		return true;

	for (i = 0; i < sched_domains_numa_levels; i++) {
		if (sched_domains_numa_distance[i] == distance)
			return true;
	}

	return false;
}

/*
 * A system can have three types of NUMA topology:
 * NUMA_DIRECT: all nodes are directly connected, or not a NUMA system
 * NUMA_GLUELESS_MESH: some nodes reachable through intermediary nodes
 * NUMA_BACKPLANE: nodes can reach other nodes through a backplane
 *
 * The difference between a glueless mesh topology and a backplane
 * topology lies in whether communication between not directly
 * connected nodes goes through intermediary nodes (where programs
 * could run), or through backplane controllers. This affects
 * placement of programs.
 *
 * The type of topology can be discerned with the following tests:
 * - If the maximum distance between any nodes is 1 hop, the system
 *   is directly connected.
 * - If for two nodes A and B, located N > 1 hops away from each other,
 *   there is an intermediary node C, which is < N hops away from both
 *   nodes A and B, the system is a glueless mesh.
 */
static void init_numa_topology_type(void)
{
	int a, b, c, n;

	n = sched_max_numa_distance;

	if (n <= 1)
		sched_numa_topology_type = NUMA_DIRECT;

	for_each_online_node(a) {
		for_each_online_node(b) {
			/* Find two nodes furthest removed from each other. */
			if (node_distance(a, b) < n)
				continue;

			/* Is there an intermediary node between a and b? */
			for_each_online_node(c) {
				if (node_distance(a, c) < n &&
				    node_distance(b, c) < n) {
					sched_numa_topology_type =
							NUMA_GLUELESS_MESH;
					return;
				}
			}

			sched_numa_topology_type = NUMA_BACKPLANE;
			return;
		}
	}
}

static void sched_init_numa(void)
{
	int next_distance, curr_distance = node_distance(0, 0);
	struct sched_domain_topology_level *tl;
	int level = 0;
	int i, j, k;

	sched_domains_numa_distance = kzalloc(sizeof(int) * nr_node_ids, GFP_KERNEL);
	if (!sched_domains_numa_distance)
		return;

	/*
	 * O(nr_nodes^2) deduplicating selection sort -- in order to find the
	 * unique distances in the node_distance() table.
	 *
	 * Assumes node_distance(0,j) includes all distances in
	 * node_distance(i,j) in order to avoid cubic time.
	 */
	next_distance = curr_distance;
	for (i = 0; i < nr_node_ids; i++) {
		for (j = 0; j < nr_node_ids; j++) {
			for (k = 0; k < nr_node_ids; k++) {
				int distance = node_distance(i, k);

				if (distance > curr_distance &&
				    (distance < next_distance ||
				     next_distance == curr_distance))
					next_distance = distance;

				/*
				 * While not a strong assumption it would be nice to know
				 * about cases where if node A is connected to B, B is not
				 * equally connected to A.
				 */
				if (sched_debug() && node_distance(k, i) != distance)
					sched_numa_warn("Node-distance not symmetric");

				if (sched_debug() && i && !find_numa_distance(distance))
					sched_numa_warn("Node-0 not representative");
			}
			if (next_distance != curr_distance) {
				sched_domains_numa_distance[level++] = next_distance;
				sched_domains_numa_levels = level;
				curr_distance = next_distance;
			} else break;
		}

		/*
		 * In case of sched_debug() we verify the above assumption.
		 */
		if (!sched_debug())
			break;
	}

	if (!level)
		return;

	/*
	 * 'level' contains the number of unique distances, excluding the
	 * identity distance node_distance(i,i).
	 *
	 * The sched_domains_numa_distance[] array includes the actual distance
	 * numbers.
	 */

	/*
	 * Here, we should temporarily reset sched_domains_numa_levels to 0.
	 * If it fails to allocate memory for array sched_domains_numa_masks[][],
	 * the array will contain less then 'level' members. This could be
	 * dangerous when we use it to iterate array sched_domains_numa_masks[][]
	 * in other functions.
	 *
	 * We reset it to 'level' at the end of this function.
	 */
	sched_domains_numa_levels = 0;

	sched_domains_numa_masks = kzalloc(sizeof(void *) * level, GFP_KERNEL);
	if (!sched_domains_numa_masks)
		return;

	/*
	 * Now for each level, construct a mask per node which contains all
	 * cpus of nodes that are that many hops away from us.
	 */
	for (i = 0; i < level; i++) {
		sched_domains_numa_masks[i] =
			kzalloc(nr_node_ids * sizeof(void *), GFP_KERNEL);
		if (!sched_domains_numa_masks[i])
			return;

		for (j = 0; j < nr_node_ids; j++) {
			struct cpumask *mask = kzalloc(cpumask_size(), GFP_KERNEL);
			if (!mask)
				return;

			sched_domains_numa_masks[i][j] = mask;

			for (k = 0; k < nr_node_ids; k++) {
				if (node_distance(j, k) > sched_domains_numa_distance[i])
					continue;

				cpumask_or(mask, mask, cpumask_of_node(k));
			}
		}
	}

	/* Compute default topology size */
	for (i = 0; sched_domain_topology[i].mask; i++);

	tl = kzalloc((i + level + 1) *
			sizeof(struct sched_domain_topology_level), GFP_KERNEL);
	if (!tl)
		return;

	/*
	 * Copy the default topology bits..
	 */
	for (i = 0; sched_domain_topology[i].mask; i++)
		tl[i] = sched_domain_topology[i];

	/*
	 * .. and append 'j' levels of NUMA goodness.
	 */
	for (j = 0; j < level; i++, j++) {
		tl[i] = (struct sched_domain_topology_level){
			.mask = sd_numa_mask,
			.sd_flags = cpu_numa_flags,
			.flags = SDTL_OVERLAP,
			.numa_level = j,
			SD_INIT_NAME(NUMA)
		};
	}

	sched_domain_topology = tl;

	sched_domains_numa_levels = level;
	sched_max_numa_distance = sched_domains_numa_distance[level - 1];

	init_numa_topology_type();
}

static void sched_domains_numa_masks_set(int cpu)
{
	int i, j;
	int node = cpu_to_node(cpu);

	for (i = 0; i < sched_domains_numa_levels; i++) {
		for (j = 0; j < nr_node_ids; j++) {
			if (node_distance(j, node) <= sched_domains_numa_distance[i])
				cpumask_set_cpu(cpu, sched_domains_numa_masks[i][j]);
		}
	}
}

static void sched_domains_numa_masks_clear(int cpu)
{
	int i, j;
	for (i = 0; i < sched_domains_numa_levels; i++) {
		for (j = 0; j < nr_node_ids; j++)
			cpumask_clear_cpu(cpu, sched_domains_numa_masks[i][j]);
	}
}

static void update_sysctl(void)
{
	unsigned int factor = get_update_sysctl_factor();


void sched_init_granularity(void)
{
	update_sysctl();
}

#define WMULT_CONST	(~0U)
#define WMULT_SHIFT	32

static void __update_inv_weight(struct load_weight *lw)
{
	unsigned long w;

	if (likely(lw->inv_weight))
		return;

	w = scale_load_down(lw->weight);

	if (BITS_PER_LONG > 32 && unlikely(w >= WMULT_CONST))
		lw->inv_weight = 1;
	else if (unlikely(!w))
		lw->inv_weight = WMULT_CONST;
	else
		lw->inv_weight = WMULT_CONST / w;
}

#define for_each_leaf_cfs_rq(rq, cfs_rq) \
	list_for_each_entry_rcu(cfs_rq, &rq->leaf_cfs_rq_list, leaf_cfs_rq_list)

/* Do the two (enqueued) entities belong to the same group ? */
static inline struct cfs_rq *
is_same_group(struct sched_entity *se, struct sched_entity *pse)
{
	if (se->cfs_rq == pse->cfs_rq)
		return se->cfs_rq;

	return NULL;
}

static inline struct sched_entity *parent_entity(struct sched_entity *se)
{
	return se->parent;
}

static void
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
	int se_depth, pse_depth;

	/*
	 * preemption test can be made between sibling entities who are in the
	 * same cfs_rq i.e who have a common parent. Walk up the hierarchy of
	 * both tasks until we find their ancestors who are siblings of common
	 * parent.
	 */

	/* First walk up until both entities are at same depth */
	se_depth = (*se)->depth;
	pse_depth = (*pse)->depth;

	while (se_depth > pse_depth) {
		se_depth--;
		*se = parent_entity(*se);
	}

	while (pse_depth > se_depth) {
		pse_depth--;
		*pse = parent_entity(*pse);
	}

	while (!is_same_group(*se, *pse)) {
		*se = parent_entity(*se);
		*pse = parent_entity(*pse);
	}
}

#else	/* !CONFIG_FAIR_GROUP_SCHED */

static inline struct task_struct *task_of(struct sched_entity *se)
{
	return container_of(se, struct task_struct, se);
}

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return container_of(cfs_rq, struct rq, cfs);
}

#define entity_is_task(se)	1

#define for_each_sched_entity(se) \
		for (; se; se = NULL)

static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
	return &task_rq(p)->cfs;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
	struct task_struct *p = task_of(se);
	struct rq *rq = task_rq(p);

	return &rq->cfs;
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
	return NULL;
}

static inline void list_add_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
}

static inline void list_del_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
}

#define for_each_leaf_cfs_rq(rq, cfs_rq) \
		for (cfs_rq = &rq->cfs; cfs_rq; cfs_rq = NULL)

static inline struct sched_entity *parent_entity(struct sched_entity *se)
{
	return NULL;
}

static inline void
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
}

#endif	/* CONFIG_FAIR_GROUP_SCHED */

static __always_inline
void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec);

/**************************************************************
 * Scheduling class tree data structure manipulation methods:
 */

static inline u64 max_vruntime(u64 max_vruntime, u64 vruntime)
{
	s64 delta = (s64)(vruntime - max_vruntime);
	if (delta > 0)
		max_vruntime = vruntime;

	return max_vruntime;
}



/*
 * Register a lock's class in the hash-table, if the class is not present
 * yet. Otherwise we look it up. We cache the result in the lock object
 * itself, so actual lookup of the hash should be once per lock object.
 */
static inline struct lock_class *
register_lock_class(struct lockdep_map *lock, unsigned int subclass, int force)
{
	struct lockdep_subclass_key *key;
	struct list_head *hash_head;
	struct lock_class *class;
	unsigned long flags;

	class = look_up_lock_class(lock, subclass);
	if (likely(class))
		goto out_set_class_cache;

	/*
	 * Debug-check: all keys must be persistent!
 	 */
	if (!static_obj(lock->key)) {
		debug_locks_off();
		printk("INFO: trying to register non-static key.\n");
		printk("the code is fine but needs lockdep annotation.\n");
		printk("turning off the locking correctness validator.\n");
		dump_stack();

		return NULL;
	}

	key = lock->key->subkeys + subclass;
	hash_head = classhashentry(key);

	raw_local_irq_save(flags);
	if (!graph_lock()) {
		raw_local_irq_restore(flags);
		return NULL;
	}
	/*
	 * We have to do the hash-walk again, to avoid races
	 * with another CPU:
	 */
	list_for_each_entry(class, hash_head, hash_entry)
		if (class->key == key)
			goto out_unlock_set;
	/*
	 * Allocate a new key from the static array, and add it to
	 * the hash:
	 */
	if (nr_lock_classes >= MAX_LOCKDEP_KEYS) {
		if (!debug_locks_off_graph_unlock()) {
			raw_local_irq_restore(flags);
			return NULL;
		}
		raw_local_irq_restore(flags);

		print_lockdep_off("BUG: MAX_LOCKDEP_KEYS too low!");
		dump_stack();
		return NULL;
	}
	class = lock_classes + nr_lock_classes++;
	debug_atomic_inc(nr_unused_locks);
	class->key = key;
	class->name = lock->name;
	class->subclass = subclass;
	INIT_LIST_HEAD(&class->lock_entry);
	INIT_LIST_HEAD(&class->locks_before);
	INIT_LIST_HEAD(&class->locks_after);
	class->name_version = count_matching_names(class);
	/*
	 * We use RCU's safe list-add method to make
	 * parallel walking of the hash-list safe:
	 */
	list_add_tail_rcu(&class->hash_entry, hash_head);
	/*
	 * Add it to the global list of classes:
	 */
	list_add_tail_rcu(&class->lock_entry, &all_lock_classes);

	if (verbose(class)) {
		graph_unlock();
		raw_local_irq_restore(flags);

		printk("\nnew class %p: %s", class->key, class->name);
		if (class->name_version > 1)
			printk("#%d", class->name_version);
		printk("\n");
		dump_stack();

		raw_local_irq_save(flags);
		if (!graph_lock()) {
			raw_local_irq_restore(flags);
			return NULL;
		}
	}
out_unlock_set:
	graph_unlock();
	raw_local_irq_restore(flags);

out_set_class_cache:
	if (!subclass || force)
		lock->class_cache[0] = class;
	else if (subclass < NR_LOCKDEP_CACHING_CLASSES)
		lock->class_cache[subclass] = class;

	/*
	 * Hash collision, did we smoke some? We found a class with a matching
	 * hash but the subclass -- which is hashed in -- didn't match.
	 */
	if (DEBUG_LOCKS_WARN_ON(class->subclass != subclass))
		return NULL;

	return class;
}

#ifdef CONFIG_PROVE_LOCKING
/*
 * Allocate a lockdep entry. (assumes the graph_lock held, returns
 * with NULL on failure)
 */
#endif
static struct lock_list *alloc_list_entry(void)
{
	if (nr_list_entries >= MAX_LOCKDEP_ENTRIES) {
		if (!debug_locks_off_graph_unlock())
			return NULL;

		print_lockdep_off("BUG: MAX_LOCKDEP_ENTRIES too low!");
		dump_stack();
		return NULL;
	}
	return list_entries + nr_list_entries++;
}



/*
 * Add a new dependency to the head of the list:
 */
static int add_lock_to_list(struct lock_class *class, struct lock_class *this,
			    struct list_head *head, unsigned long ip,
			    int distance, struct stack_trace *trace)
{
	struct lock_list *entry;
	/*
	 * Lock not present yet - get a new dependency struct and
	 * add it to the list:
	 */
	entry = alloc_list_entry();
	if (!entry)
		return 0;

	entry->class = this;
	entry->distance = distance;
	entry->trace = *trace;
	/*
	 * Since we never remove from the dependency list, the list can
	 * be walked lockless by other CPUs, it's only allocation
	 * that must be protected by the spinlock. But this also means
	 * we must make new entries visible only once writes to the
	 * entry become visible - hence the RCU op:
	 */
	list_add_tail_rcu(&entry->entry, head);

	return 1;
}

/*
 * For good efficiency of modular, we use power of 2
 */
#define MAX_CIRCULAR_QUEUE_SIZE		4096UL
#define CQ_MASK				(MAX_CIRCULAR_QUEUE_SIZE-1)

/*
 * The circular_queue and helpers is used to implement the
 * breadth-first search(BFS)algorithem, by which we can build
 * the shortest path from the next lock to be acquired to the
 * previous held lock if there is a circular between them.
 */
struct circular_queue {
	unsigned long element[MAX_CIRCULAR_QUEUE_SIZE];
	unsigned int  front, rear;
};

static struct circular_queue lock_cq;

unsigned int max_bfs_queue_depth;

static unsigned int lockdep_dependency_gen_id;

static inline void __cq_init(struct circular_queue *cq)
{
	cq->front = cq->rear = 0;
	lockdep_dependency_gen_id++;
}

static inline int __cq_empty(struct circular_queue *cq)
{
	return (cq->front == cq->rear);
}

static inline int __cq_full(struct circular_queue *cq)
{
	return ((cq->rear + 1) & CQ_MASK) == cq->front;
}

static inline int __cq_enqueue(struct circular_queue *cq, unsigned long elem)
{
	if (__cq_full(cq))
		return -1;

	cq->element[cq->rear] = elem;
	cq->rear = (cq->rear + 1) & CQ_MASK;
	return 0;
}

static inline int __cq_dequeue(struct circular_queue *cq, unsigned long *elem)
{
	if (__cq_empty(cq))
		return -1;

	*elem = cq->element[cq->front];
	cq->front = (cq->front + 1) & CQ_MASK;
	return 0;
}

static inline unsigned int  __cq_get_elem_count(struct circular_queue *cq)
{
	return (cq->rear - cq->front) & CQ_MASK;
}

static inline void mark_lock_accessed(struct lock_list *lock,
					struct lock_list *parent)
{
	unsigned long nr;

	nr = lock - list_entries;
	WARN_ON(nr >= nr_list_entries); /* Out-of-bounds, input fail */
	lock->parent = parent;
	lock->class->dep_gen_id = lockdep_dependency_gen_id;
}

static inline unsigned long lock_accessed(struct lock_list *lock)
{
	unsigned long nr;

	nr = lock - list_entries;
	WARN_ON(nr >= nr_list_entries); /* Out-of-bounds, input fail */
	return lock->class->dep_gen_id == lockdep_dependency_gen_id;
}

static inline struct lock_list *get_lock_parent(struct lock_list *child)
{
	return child->parent;
}

static inline int get_lock_depth(struct lock_list *child)
{
	int depth = 0;
	struct lock_list *parent;

	while ((parent = get_lock_parent(child))) {
		child = parent;
		depth++;
	}
	return depth;
}

static int __bfs(struct lock_list *source_entry,
		 void *data,
		 int (*match)(struct lock_list *entry, void *data),
		 struct lock_list **target_entry,
		 int forward)
{
	struct lock_list *entry;
	struct list_head *head;
	struct circular_queue *cq = &lock_cq;
	int ret = 1;

	if (match(source_entry, data)) {
		*target_entry = source_entry;
		ret = 0;
		goto exit;
	}

	if (forward)
		head = &source_entry->class->locks_after;
	else
		head = &source_entry->class->locks_before;

	if (list_empty(head))
		goto exit;

	__cq_init(cq);
	__cq_enqueue(cq, (unsigned long)source_entry);

	while (!__cq_empty(cq)) {
		struct lock_list *lock;

		__cq_dequeue(cq, (unsigned long *)&lock);

		if (!lock->class) {
			ret = -2;
			goto exit;
		}

		if (forward)
			head = &lock->class->locks_after;
		else
			head = &lock->class->locks_before;

		list_for_each_entry(entry, head, entry) {
			if (!lock_accessed(entry)) {
				unsigned int cq_depth;
				mark_lock_accessed(entry, lock);
				if (match(entry, data)) {
					*target_entry = entry;
					ret = 0;
					goto exit;
				}

				if (__cq_enqueue(cq, (unsigned long)entry)) {
					ret = -1;
					goto exit;
				}
				cq_depth = __cq_get_elem_count(cq);
				if (max_bfs_queue_depth < cq_depth)
					max_bfs_queue_depth = cq_depth;
			}
		}
	}
exit:
	return ret;
}

static inline int __bfs_forwards(struct lock_list *src_entry,
			void *data,
			int (*match)(struct lock_list *entry, void *data),
			struct lock_list **target_entry)
{
	return __bfs(src_entry, data, match, target_entry, 1);

}

static inline int __bfs_backwards(struct lock_list *src_entry,
			void *data,
			int (*match)(struct lock_list *entry, void *data),
			struct lock_list **target_entry)
{
	return __bfs(src_entry, data, match, target_entry, 0);

}

/*
 * Recursive, forwards-direction lock-dependency checking, used for
 * both noncyclic checking and for hardirq-unsafe/softirq-unsafe
 * checking.
 */

/*
 * Print a dependency chain entry (this is only done when a deadlock
 * has been detected):
 */
static noinline int
print_circular_bug_entry(struct lock_list *target, int depth)
{
	if (debug_locks_silent)
		return 0;
	printk("\n-> #%u", depth);
	print_lock_name(target->class);
	printk(":\n");
	print_stack_trace(&target->trace, 6);

	return 0;
}

static void
print_circular_lock_scenario(struct held_lock *src,
			     struct held_lock *tgt,
			     struct lock_list *prt)
{
	struct lock_class *source = hlock_class(src);
	struct lock_class *target = hlock_class(tgt);
	struct lock_class *parent = prt->class;

	/*
	 * A direct locking problem where unsafe_class lock is taken
	 * directly by safe_class lock, then all we need to show
	 * is the deadlock scenario, as it is obvious that the
	 * unsafe lock is taken under the safe lock.
	 *
	 * But if there is a chain instead, where the safe lock takes
	 * an intermediate lock (middle_class) where this lock is
	 * not the same as the safe lock, then the lock chain is
	 * used to describe the problem. Otherwise we would need
	 * to show a different CPU case for each link in the chain
	 * from the safe_class lock to the unsafe_class lock.
	 */
	if (parent != source) {
		printk("Chain exists of:\n  ");
		__print_lock_name(source);
		printk(" --> ");
		__print_lock_name(parent);
		printk(" --> ");
		__print_lock_name(target);
		printk("\n\n");
	}

	printk(" Possible unsafe locking scenario:\n\n");
	printk("       CPU0                    CPU1\n");
	printk("       ----                    ----\n");
	printk("  lock(");
	__print_lock_name(target);
	printk(");\n");
	printk("                               lock(");
	__print_lock_name(parent);
	printk(");\n");
	printk("                               lock(");
	__print_lock_name(target);
	printk(");\n");
	printk("  lock(");
	__print_lock_name(source);
	printk(");\n");
	printk("\n *** DEADLOCK ***\n\n");
}

/*
 * When a circular dependency is detected, print the
 * header first:
 */
static noinline int
print_circular_bug_header(struct lock_list *entry, unsigned int depth,
			struct held_lock *check_src,
			struct held_lock *check_tgt)
{
	struct task_struct *curr = current;

	if (debug_locks_silent)
		return 0;

	printk("\n");
	printk("======================================================\n");
	printk("[ INFO: possible circular locking dependency detected ]\n");
	print_kernel_ident();
	printk("-------------------------------------------------------\n");
	printk("%s/%d is trying to acquire lock:\n",
		curr->comm, task_pid_nr(curr));
	print_lock(check_src);
	printk("\nbut task is already holding lock:\n");
	print_lock(check_tgt);
	printk("\nwhich lock already depends on the new lock.\n\n");
	printk("\nthe existing dependency chain (in reverse order) is:\n");

	print_circular_bug_entry(entry, depth);

	return 0;
}

static inline int class_equal(struct lock_list *entry, void *data)
{
	return entry->class == data;
}

static noinline int print_circular_bug(struct lock_list *this,
				struct lock_list *target,
				struct held_lock *check_src,
				struct held_lock *check_tgt)
{
	struct task_struct *curr = current;
	struct lock_list *parent;
	struct lock_list *first_parent;
	int depth;

	if (!debug_locks_off_graph_unlock() || debug_locks_silent)
		return 0;

	if (!save_trace(&this->trace))
		return 0;

	depth = get_lock_depth(target);

	print_circular_bug_header(target, depth, check_src, check_tgt);

	parent = get_lock_parent(target);
	first_parent = parent;

	while (parent) {
		print_circular_bug_entry(parent, --depth);
		parent = get_lock_parent(parent);
	}

	printk("\nother info that might help us debug this:\n\n");
	print_circular_lock_scenario(check_src, check_tgt,
				     first_parent);

	lockdep_print_held_locks(curr);

	printk("\nstack backtrace:\n");
	dump_stack();

	return 0;
}

static noinline int print_bfs_bug(int ret)
{
	if (!debug_locks_off_graph_unlock())
		return 0;

	/*
	 * Breadth-first-search failed, graph got corrupted?
	 */
	WARN(1, "lockdep bfs error:%d\n", ret);

	return 0;
}

static int noop_count(struct lock_list *entry, void *data)
{
	(*(unsigned long *)data)++;
	return 0;
}

static unsigned long __lockdep_count_forward_deps(struct lock_list *this)
{
	unsigned long  count = 0;
	struct lock_list *uninitialized_var(target_entry);

	__bfs_forwards(this, (void *)&count, noop_count, &target_entry);

	return count;
}
unsigned long lockdep_count_forward_deps(struct lock_class *class)
{
	unsigned long ret, flags;
	struct lock_list this;

	this.parent = NULL;
	this.class = class;

	local_irq_save(flags);
	arch_spin_lock(&lockdep_lock);
	ret = __lockdep_count_forward_deps(&this);
	arch_spin_unlock(&lockdep_lock);
	local_irq_restore(flags);

	return ret;
}

static unsigned long __lockdep_count_backward_deps(struct lock_list *this)
{
	unsigned long  count = 0;
	struct lock_list *uninitialized_var(target_entry);

	__bfs_backwards(this, (void *)&count, noop_count, &target_entry);

	return count;
}

unsigned long lockdep_count_backward_deps(struct lock_class *class)
{
	unsigned long ret, flags;
	struct lock_list this;

	this.parent = NULL;
	this.class = class;

	local_irq_save(flags);
	arch_spin_lock(&lockdep_lock);
	ret = __lockdep_count_backward_deps(&this);
	arch_spin_unlock(&lockdep_lock);
	local_irq_restore(flags);

	return ret;
}

/*
 * Prove that the dependency graph starting at <entry> can not
 * lead to <target>. Print an error and return 0 if it does.
 */
static noinline int
check_noncircular(struct lock_list *root, struct lock_class *target,
		struct lock_list **target_entry)
{
	int result;

	debug_atomic_inc(nr_cyclic_checks);

	result = __bfs_forwards(root, target, class_equal, target_entry);

	return result;
}

#if defined(CONFIG_TRACE_IRQFLAGS) && defined(CONFIG_PROVE_LOCKING)
/*
 * Forwards and backwards subgraph searching, for the purposes of
 * proving that two subgraphs can be connected by a new dependency
 * without creating any illegal irq-safe -> irq-unsafe lock dependency.
 */


static inline int usage_match(struct lock_list *entry, void *bit)
{
	return entry->class->usage_mask & (1 << (enum lock_usage_bit)bit);
}


#endif
/*
 * Find a node in the forwards-direction dependency sub-graph starting
 * at @root->class that matches @bit.
 *
 * Return 0 if such a node exists in the subgraph, and put that node
 * into *@target_entry.
 *
 * Return 1 otherwise and keep *@target_entry unchanged.
 * Return <0 on error.
 */
static int
find_usage_forwards(struct lock_list *root, enum lock_usage_bit bit,
			struct lock_list **target_entry)
{
	int result;

	debug_atomic_inc(nr_find_usage_forwards_checks);

	result = __bfs_forwards(root, (void *)bit, usage_match, target_entry);

	return result;
}

/*
 * Find a node in the backwards-direction dependency sub-graph starting
 * at @root->class that matches @bit.
 *
 * Return 0 if such a node exists in the subgraph, and put that node
 * into *@target_entry.
 *
 * Return 1 otherwise and keep *@target_entry unchanged.
 * Return <0 on error.
 */
static int
find_usage_backwards(struct lock_list *root, enum lock_usage_bit bit,
			struct lock_list **target_entry)
{
	int result;

	debug_atomic_inc(nr_find_usage_backwards_checks);

	result = __bfs_backwards(root, (void *)bit, usage_match, target_entry);

	return result;
}

static void print_lock_class_header(struct lock_class *class, int depth)
{
	int bit;

	printk("%*s->", depth, "");
	print_lock_name(class);
	printk(" ops: %lu", class->ops);
	printk(" {\n");

	for (bit = 0; bit < LOCK_USAGE_STATES; bit++) {
		if (class->usage_mask & (1 << bit)) {
			int len = depth;

			len += printk("%*s   %s", depth, "", usage_str[bit]);
			len += printk(" at:\n");
			print_stack_trace(class->usage_traces + bit, len);
		}
	}
	printk("%*s }\n", depth, "");

	printk("%*s ... key      at: ",depth,"");
	print_ip_sym((unsigned long)class->key);
}

/*
 * printk the shortest lock dependencies from @start to @end in reverse order:
 */
static void __used
print_shortest_lock_dependencies(struct lock_list *leaf,
				struct lock_list *root)
{
	struct lock_list *entry = leaf;
	int depth;

	/*compute depth from generated tree by BFS*/
	depth = get_lock_depth(leaf);

	do {
		print_lock_class_header(entry->class, depth);
		printk("%*s ... acquired at:\n", depth, "");
		print_stack_trace(&entry->trace, 2);
		printk("\n");

		if (depth == 0 && (entry != root)) {
			printk("lockdep:%s bad path found in chain graph\n", __func__);
			break;
		}

		entry = get_lock_parent(entry);
		depth--;
	} while (entry && (depth >= 0));

	return;
}


/*
 * The "str" argument may point to something like  | grep xyz
 */
static void parse_grep(const char *str)
{
	int	len;
	char	*cp = (char *)str, *cp2;

	/* sanity check: we should have been called with the \ first */
	if (*cp != '|')
		return;
	cp++;
	while (isspace(*cp))
		cp++;
	if (strncmp(cp, "grep ", 5)) {
		kdb_printf("invalid 'pipe', see grephelp\n");
		return;
	}
	cp += 5;
	while (isspace(*cp))
		cp++;
	cp2 = strchr(cp, '\n');
	if (cp2)
		*cp2 = '\0'; /* remove the trailing newline */
	len = strlen(cp);
	if (len == 0) {
		kdb_printf("invalid 'pipe', see grephelp\n");
		return;
	}
	/* now cp points to a nonzero length search string */
	if (*cp == '"') {
		/* allow it be "x y z" by removing the "'s - there must
		   be two of them */
		cp++;
		cp2 = strchr(cp, '"');
		if (!cp2) {
			kdb_printf("invalid quoted string, see grephelp\n");
			return;
		}
		*cp2 = '\0'; /* end the string where the 2nd " was */
	}
	kdb_grep_leading = 0;
	if (*cp == '^') {
		kdb_grep_leading = 1;
		cp++;
	}
	len = strlen(cp);
	kdb_grep_trailing = 0;
	if (*(cp+len-1) == '$') {
		kdb_grep_trailing = 1;
		*(cp+len-1) = '\0';
	}
	len = strlen(cp);
	if (!len)
		return;
	if (len >= GREP_LEN) {
		kdb_printf("search string too long\n");
		return;
	}
	strcpy(kdb_grep_string, cp);
	kdb_grepping_flag++;
	return;
}

/*
 * kdb_parse - Parse the command line, search the command table for a
 *	matching command and invoke the command function.  This
 *	function may be called recursively, if it is, the second call
 *	will overwrite argv and cbuf.  It is the caller's
 *	responsibility to save their argv if they recursively call
 *	kdb_parse().
 * Parameters:
 *      cmdstr	The input command line to be parsed.
 *	regs	The registers at the time kdb was entered.
 * Returns:
 *	Zero for success, a kdb diagnostic if failure.
 * Remarks:
 *	Limited to 20 tokens.
 *
 *	Real rudimentary tokenization. Basically only whitespace
 *	is considered a token delimeter (but special consideration
 *	is taken of the '=' sign as used by the 'set' command).
 *
 *	The algorithm used to tokenize the input string relies on
 *	there being at least one whitespace (or otherwise useless)
 *	character between tokens as the character immediately following
 *	the token is altered in-place to a null-byte to terminate the
 *	token string.
 */

#define MAXARGC	20

int kdb_parse(const char *cmdstr)
{
	static char *argv[MAXARGC];
	static int argc;
	static char cbuf[CMD_BUFLEN+2];
	char *cp;
	char *cpp, quoted;
	kdbtab_t *tp;
	int i, escaped, ignore_errors = 0, check_grep;

	/*
	 * First tokenize the command string.
	 */
	cp = (char *)cmdstr;
	kdb_grepping_flag = check_grep = 0;

	if (KDB_FLAG(CMD_INTERRUPT)) {
		/* Previous command was interrupted, newline must not
		 * repeat the command */
		KDB_FLAG_CLEAR(CMD_INTERRUPT);
		KDB_STATE_SET(PAGER);
		argc = 0;	/* no repeat */
	}

	if (*cp != '\n' && *cp != '\0') {
		argc = 0;
		cpp = cbuf;
		while (*cp) {
			/* skip whitespace */
			while (isspace(*cp))
				cp++;
			if ((*cp == '\0') || (*cp == '\n') ||
			    (*cp == '#' && !defcmd_in_progress))
				break;
			/* special case: check for | grep pattern */
			if (*cp == '|') {
				check_grep++;
				break;
			}
			if (cpp >= cbuf + CMD_BUFLEN) {
				kdb_printf("kdb_parse: command buffer "
					   "overflow, command ignored\n%s\n",
					   cmdstr);
				return KDB_NOTFOUND;
			}
			if (argc >= MAXARGC - 1) {
				kdb_printf("kdb_parse: too many arguments, "
					   "command ignored\n%s\n", cmdstr);
				return KDB_NOTFOUND;
			}
			argv[argc++] = cpp;
			escaped = 0;
			quoted = '\0';
			/* Copy to next unquoted and unescaped
			 * whitespace or '=' */
			while (*cp && *cp != '\n' &&
			       (escaped || quoted || !isspace(*cp))) {
				if (cpp >= cbuf + CMD_BUFLEN)
					break;
				if (escaped) {
					escaped = 0;
					*cpp++ = *cp++;
					continue;
				}
				if (*cp == '\\') {
					escaped = 1;
					++cp;
					continue;
				}
				if (*cp == quoted)
					quoted = '\0';
				else if (*cp == '\'' || *cp == '"')
					quoted = *cp;
				*cpp = *cp++;
				if (*cpp == '=' && !quoted)
					break;
				++cpp;
			}
			*cpp++ = '\0';	/* Squash a ws or '=' character */
		}
	}
	if (!argc)
		return 0;
	if (check_grep)
		parse_grep(cp);
	if (defcmd_in_progress) {
		int result = kdb_defcmd2(cmdstr, argv[0]);
		if (!defcmd_in_progress) {
			argc = 0;	/* avoid repeat on endefcmd */
			*(argv[0]) = '\0';
		}
		return result;
	}
	if (argv[0][0] == '-' && argv[0][1] &&
	    (argv[0][1] < '0' || argv[0][1] > '9')) {
		ignore_errors = 1;
		++argv[0];
	}

	for_each_kdbcmd(tp, i) {
		if (tp->cmd_name) {
			/*
			 * If this command is allowed to be abbreviated,
			 * check to see if this is it.
			 */

			if (tp->cmd_minlen
			 && (strlen(argv[0]) <= tp->cmd_minlen)) {
				if (strncmp(argv[0],
					    tp->cmd_name,
					    tp->cmd_minlen) == 0) {
					break;
				}
			}

			if (strcmp(argv[0], tp->cmd_name) == 0)
				break;
		}
	}

	/*
	 * If we don't find a command by this name, see if the first
	 * few characters of this match any of the known commands.
	 * e.g., md1c20 should match md.
	 */
	if (i == kdb_max_commands) {
		for_each_kdbcmd(tp, i) {
			if (tp->cmd_name) {
				if (strncmp(argv[0],
					    tp->cmd_name,
					    strlen(tp->cmd_name)) == 0) {
					break;
				}
			}
		}
	}

	if (i < kdb_max_commands) {
		int result;

		if (!kdb_check_flags(tp->cmd_flags, kdb_cmd_enabled, argc <= 1))
			return KDB_NOPERM;

		KDB_STATE_SET(CMD);
		result = (*tp->cmd_func)(argc-1, (const char **)argv);
		if (result && ignore_errors && result > KDB_CMD_GO)
			result = 0;
		KDB_STATE_CLEAR(CMD);

		if (tp->cmd_flags & KDB_REPEAT_WITH_ARGS)
			return result;

		argc = tp->cmd_flags & KDB_REPEAT_NO_ARGS ? 1 : 0;
		if (argv[argc])
			*(argv[argc]) = '\0';
		return result;
	}

	/*
	 * If the input with which we were presented does not
	 * map to an existing command, attempt to parse it as an
	 * address argument and display the result.   Useful for
	 * obtaining the address of a variable, or the nearest symbol
	 * to an address contained in a register.
	 */
	{
		unsigned long value;
		char *name = NULL;
		long offset;
		int nextarg = 0;

		if (kdbgetaddrarg(0, (const char **)argv, &nextarg,
				  &value, &offset, &name)) {
			return KDB_NOTFOUND;
		}

		kdb_printf("%s = ", argv[0]);
		kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);
		kdb_printf("\n");
		return 0;
	}
}


static int handle_ctrl_cmd(char *cmd)
{
#define CTRL_P	16
#define CTRL_N	14

	/* initial situation */
	if (cmd_head == cmd_tail)
		return 0;
	switch (*cmd) {
	case CTRL_P:
		if (cmdptr != cmd_tail)
			cmdptr = (cmdptr-1) % KDB_CMD_HISTORY_COUNT;
		strncpy(cmd_cur, cmd_hist[cmdptr], CMD_BUFLEN);
		return 1;
	case CTRL_N:
		if (cmdptr != cmd_head)
			cmdptr = (cmdptr+1) % KDB_CMD_HISTORY_COUNT;
		strncpy(cmd_cur, cmd_hist[cmdptr], CMD_BUFLEN);
		return 1;
	}
	return 0;
}

/*
 * kdb_reboot - This function implements the 'reboot' command.  Reboot
 *	the system immediately, or loop for ever on failure.
 */
static int kdb_reboot(int argc, const char **argv)
{
	emergency_restart();
	kdb_printf("Hmm, kdb_reboot did not reboot, spinning here\n");
	while (1)
		cpu_relax();
	/* NOTREACHED */
	return 0;
}

static void kdb_dumpregs(struct pt_regs *regs)
{
	int old_lvl = console_loglevel;
	console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;
	kdb_trap_printk++;
	show_regs(regs);
	kdb_trap_printk--;
	kdb_printf("\n");
	console_loglevel = old_lvl;
}

void kdb_set_current_task(struct task_struct *p)
{
	kdb_current_task = p;

	if (kdb_task_has_cpu(p)) {
		kdb_current_regs = KDB_TSKREGS(kdb_process_cpu(p));
		return;
	}
	kdb_current_regs = NULL;
}

/*
 * kdb_local - The main code for kdb.  This routine is invoked on a
 *	specific processor, it is not global.  The main kdb() routine
 *	ensures that only one processor at a time is in this routine.
 *	This code is called with the real reason code on the first
 *	entry to a kdb session, thereafter it is called with reason
 *	SWITCH, even if the user goes back to the original cpu.
 * Inputs:
 *	reason		The reason KDB was invoked
 *	error		The hardware-defined error code
 *	regs		The exception frame at time of fault/breakpoint.
 *	db_result	Result code from the break or debug point.
 * Returns:
 *	0	KDB was invoked for an event which it wasn't responsible
 *	1	KDB handled the event for which it was invoked.
 *	KDB_CMD_GO	User typed 'go'.
 *	KDB_CMD_CPU	User switched to another cpu.
 *	KDB_CMD_SS	Single step.
 */
static int kdb_local(kdb_reason_t reason, int error, struct pt_regs *regs,
		     kdb_dbtrap_t db_result)
{
	char *cmdbuf;
	int diag;
	struct task_struct *kdb_current =
		kdb_curr_task(raw_smp_processor_id());

	KDB_DEBUG_STATE("kdb_local 1", reason);
	kdb_go_count = 0;
	if (reason == KDB_REASON_DEBUG) {
		/* special case below */
	} else {
		kdb_printf("\nEntering kdb (current=0x%p, pid %d) ",
			   kdb_current, kdb_current ? kdb_current->pid : 0);
#if defined(CONFIG_SMP)
		kdb_printf("on processor %d ", raw_smp_processor_id());
#endif
	}

	switch (reason) {
	case KDB_REASON_DEBUG:
	{
		/*
		 * If re-entering kdb after a single step
		 * command, don't print the message.
		 */
		switch (db_result) {
		case KDB_DB_BPT:
			kdb_printf("\nEntering kdb (0x%p, pid %d) ",
				   kdb_current, kdb_current->pid);
#if defined(CONFIG_SMP)
			kdb_printf("on processor %d ", raw_smp_processor_id());
#endif
			kdb_printf("due to Debug @ " kdb_machreg_fmt "\n",
				   instruction_pointer(regs));
			break;
		case KDB_DB_SS:
			break;
		case KDB_DB_SSBPT:
			KDB_DEBUG_STATE("kdb_local 4", reason);
			return 1;	/* kdba_db_trap did the work */
		default:
			kdb_printf("kdb: Bad result from kdba_db_trap: %d\n",
				   db_result);
			break;
		}

	}
		break;
	case KDB_REASON_ENTER:
		if (KDB_STATE(KEYBOARD))
			kdb_printf("due to Keyboard Entry\n");
		else
			kdb_printf("due to KDB_ENTER()\n");
		break;
	case KDB_REASON_KEYBOARD:
		KDB_STATE_SET(KEYBOARD);
		kdb_printf("due to Keyboard Entry\n");
		break;
	case KDB_REASON_ENTER_SLAVE:
		/* drop through, slaves only get released via cpu switch */
	case KDB_REASON_SWITCH:
		kdb_printf("due to cpu switch\n");
		break;
	case KDB_REASON_OOPS:
		kdb_printf("Oops: %s\n", kdb_diemsg);
		kdb_printf("due to oops @ " kdb_machreg_fmt "\n",
			   instruction_pointer(regs));
		kdb_dumpregs(regs);
		break;
	case KDB_REASON_SYSTEM_NMI:
		kdb_printf("due to System NonMaskable Interrupt\n");
		break;
	case KDB_REASON_NMI:
		kdb_printf("due to NonMaskable Interrupt @ "
			   kdb_machreg_fmt "\n",
			   instruction_pointer(regs));
		kdb_dumpregs(regs);
		break;
	case KDB_REASON_SSTEP:
	case KDB_REASON_BREAK:
		kdb_printf("due to %s @ " kdb_machreg_fmt "\n",
			   reason == KDB_REASON_BREAK ?
			   "Breakpoint" : "SS trap", instruction_pointer(regs));
		/*
		 * Determine if this breakpoint is one that we
		 * are interested in.
		 */
		if (db_result != KDB_DB_BPT) {
			kdb_printf("kdb: error return from kdba_bp_trap: %d\n",
				   db_result);
			KDB_DEBUG_STATE("kdb_local 6", reason);
			return 0;	/* Not for us, dismiss it */
		}
		break;
	case KDB_REASON_RECURSE:
		kdb_printf("due to Recursion @ " kdb_machreg_fmt "\n",
			   instruction_pointer(regs));
		break;
	default:
		kdb_printf("kdb: unexpected reason code: %d\n", reason);
		KDB_DEBUG_STATE("kdb_local 8", reason);
		return 0;	/* Not for us, dismiss it */
	}

	while (1) {
		/*
		 * Initialize pager context.
		 */
		kdb_nextline = 1;
		KDB_STATE_CLEAR(SUPPRESS);

		cmdbuf = cmd_cur;
		*cmdbuf = '\0';
		*(cmd_hist[cmd_head]) = '\0';

do_full_getstr:
#if defined(CONFIG_SMP)
		snprintf(kdb_prompt_str, CMD_BUFLEN, kdbgetenv("PROMPT"),
			 raw_smp_processor_id());
#else
		snprintf(kdb_prompt_str, CMD_BUFLEN, kdbgetenv("PROMPT"));
#endif
		if (defcmd_in_progress)
			strncat(kdb_prompt_str, "[defcmd]", CMD_BUFLEN);

		/*
		 * Fetch command from keyboard
		 */
		cmdbuf = kdb_getstr(cmdbuf, CMD_BUFLEN, kdb_prompt_str);
		if (*cmdbuf != '\n') {
			if (*cmdbuf < 32) {
				if (cmdptr == cmd_head) {
					strncpy(cmd_hist[cmd_head], cmd_cur,
						CMD_BUFLEN);
					*(cmd_hist[cmd_head] +
					  strlen(cmd_hist[cmd_head])-1) = '\0';
				}
				if (!handle_ctrl_cmd(cmdbuf))
					*(cmd_cur+strlen(cmd_cur)-1) = '\0';
				cmdbuf = cmd_cur;
				goto do_full_getstr;
			} else {
				strncpy(cmd_hist[cmd_head], cmd_cur,
					CMD_BUFLEN);
			}

			cmd_head = (cmd_head+1) % KDB_CMD_HISTORY_COUNT;
			if (cmd_head == cmd_tail)
				cmd_tail = (cmd_tail+1) % KDB_CMD_HISTORY_COUNT;
		}

		cmdptr = cmd_head;
		diag = kdb_parse(cmdbuf);
		if (diag == KDB_NOTFOUND) {
			kdb_printf("Unknown kdb command: '%s'\n", cmdbuf);
			diag = 0;
		}
		if (diag == KDB_CMD_GO
		 || diag == KDB_CMD_CPU
		 || diag == KDB_CMD_SS
		 || diag == KDB_CMD_KGDB)
			break;

		if (diag)
			kdb_cmderror(diag);
	}
	KDB_DEBUG_STATE("kdb_local 9", diag);
	return diag;
}


/*
 * kdb_print_state - Print the state data for the current processor
 *	for debugging.
 * Inputs:
 *	text		Identifies the debug point
 *	value		Any integer value to be printed, e.g. reason code.
 */
void kdb_print_state(const char *text, int value)
{
	kdb_printf("state: %s cpu %d value %d initial %d state %x\n",
		   text, raw_smp_processor_id(), value, kdb_initial_cpu,
		   kdb_state);
}

/*
 * kdb_main_loop - After initial setup and assignment of the
 *	controlling cpu, all cpus are in this loop.  One cpu is in
 *	control and will issue the kdb prompt, the others will spin
 *	until 'go' or cpu switch.
 *
 *	To get a consistent view of the kernel stacks for all
 *	processes, this routine is invoked from the main kdb code via
 *	an architecture specific routine.  kdba_main_loop is
 *	responsible for making the kernel stacks consistent for all
 *	processes, there should be no difference between a blocked
 *	process and a running process as far as kdb is concerned.
 * Inputs:
 *	reason		The reason KDB was invoked
 *	error		The hardware-defined error code
 *	reason2		kdb's current reason code.
 *			Initially error but can change
 *			according to kdb state.
 *	db_result	Result code from break or debug point.
 *	regs		The exception frame at time of fault/breakpoint.
 *			should always be valid.
 * Returns:
 *	0	KDB was invoked for an event which it wasn't responsible
 *	1	KDB handled the event for which it was invoked.
 */
int kdb_main_loop(kdb_reason_t reason, kdb_reason_t reason2, int error,
	      kdb_dbtrap_t db_result, struct pt_regs *regs)
{
	int result = 1;
	/* Stay in kdb() until 'go', 'ss[b]' or an error */
	while (1) {
		/*
		 * All processors except the one that is in control
		 * will spin here.
		 */
		KDB_DEBUG_STATE("kdb_main_loop 1", reason);
		while (KDB_STATE(HOLD_CPU)) {
			/* state KDB is turned off by kdb_cpu to see if the
			 * other cpus are still live, each cpu in this loop
			 * turns it back on.
			 */
			if (!KDB_STATE(KDB))
				KDB_STATE_SET(KDB);
		}

		KDB_STATE_CLEAR(SUPPRESS);
		KDB_DEBUG_STATE("kdb_main_loop 2", reason);
		if (KDB_STATE(LEAVING))
			break;	/* Another cpu said 'go' */
		/* Still using kdb, this processor is in control */
		result = kdb_local(reason2, error, regs, db_result);
		KDB_DEBUG_STATE("kdb_main_loop 3", result);

		if (result == KDB_CMD_CPU)
			break;

		if (result == KDB_CMD_SS) {
			KDB_STATE_SET(DOING_SS);
			break;
		}

		if (result == KDB_CMD_KGDB) {
			if (!KDB_STATE(DOING_KGDB))
				kdb_printf("Entering please attach debugger "
					   "or use $D#44+ or $3#33\n");
			break;
		}
		if (result && result != 1 && result != KDB_CMD_GO)
			kdb_printf("\nUnexpected kdb_local return code %d\n",
				   result);
		KDB_DEBUG_STATE("kdb_main_loop 4", reason);
		break;
	}
	if (KDB_STATE(DOING_SS))
		KDB_STATE_CLEAR(SSBPT);

	/* Clean up any keyboard devices before leaving */
	kdb_kbd_cleanup_state();

	return result;
}

/*
 * kdb_mdr - This function implements the guts of the 'mdr', memory
 * read command.
 *	mdr  <addr arg>,<byte count>
 * Inputs:
 *	addr	Start address
 *	count	Number of bytes
 * Returns:
 *	Always 0.  Any errors are detected and printed by kdb_getarea.
 */
static int kdb_mdr(unsigned long addr, unsigned int count)
{
	unsigned char c;
	while (count--) {
		if (kdb_getarea(c, addr))
			return 0;
		kdb_printf("%02x", c);
		addr++;
	}
	kdb_printf("\n");
	return 0;
}

/*
 * kdb_md - This function implements the 'md', 'md1', 'md2', 'md4',
 *	'md8' 'mdr' and 'mds' commands.
 *
 *	md|mds  [<addr arg> [<line count> [<radix>]]]
 *	mdWcN	[<addr arg> [<line count> [<radix>]]]
 *		where W = is the width (1, 2, 4 or 8) and N is the count.
 *		for eg., md1c20 reads 20 bytes, 1 at a time.
 *	mdr  <addr arg>,<byte count>
 */
static void kdb_md_line(const char *fmtstr, unsigned long addr,
			int symbolic, int nosect, int bytesperword,
			int num, int repeat, int phys)
{
	/* print just one line of data */
	kdb_symtab_t symtab;
	char cbuf[32];
	char *c = cbuf;
	int i;
	unsigned long word;

	memset(cbuf, '\0', sizeof(cbuf));
	if (phys)
		kdb_printf("phys " kdb_machreg_fmt0 " ", addr);
	else
		kdb_printf(kdb_machreg_fmt0 " ", addr);

	for (i = 0; i < num && repeat--; i++) {
		if (phys) {
			if (kdb_getphysword(&word, addr, bytesperword))
				break;
		} else if (kdb_getword(&word, addr, bytesperword))
			break;
		kdb_printf(fmtstr, word);
		if (symbolic)
			kdbnearsym(word, &symtab);
		else
			memset(&symtab, 0, sizeof(symtab));
		if (symtab.sym_name) {
			kdb_symbol_print(word, &symtab, 0);
			if (!nosect) {
				kdb_printf("\n");
				kdb_printf("                       %s %s "
					   kdb_machreg_fmt " "
					   kdb_machreg_fmt " "
					   kdb_machreg_fmt, symtab.mod_name,
					   symtab.sec_name, symtab.sec_start,
					   symtab.sym_start, symtab.sym_end);
			}
			addr += bytesperword;
		} else {
			union {
				u64 word;
				unsigned char c[8];
			} wc;
			unsigned char *cp;
#ifdef	__BIG_ENDIAN
			cp = wc.c + 8 - bytesperword;
#else
			cp = wc.c;
#endif
			wc.word = word;
#define printable_char(c) \
	({unsigned char __c = c; isascii(__c) && isprint(__c) ? __c : '.'; })
			switch (bytesperword) {
			case 8:
				*c++ = printable_char(*cp++);
				*c++ = printable_char(*cp++);
				*c++ = printable_char(*cp++);
				*c++ = printable_char(*cp++);
				addr += 4;
			case 4:
				*c++ = printable_char(*cp++);
				*c++ = printable_char(*cp++);
				addr += 2;
			case 2:
				*c++ = printable_char(*cp++);
				addr++;
			case 1:
				*c++ = printable_char(*cp++);
				addr++;
				break;
			}
#undef printable_char
		}
	}
	kdb_printf("%*s %s\n", (int)((num-i)*(2*bytesperword + 1)+1),
		   " ", cbuf);
}

static int kdb_md(int argc, const char **argv)
{
	static unsigned long last_addr;
	static int last_radix, last_bytesperword, last_repeat;
	int radix = 16, mdcount = 8, bytesperword = KDB_WORD_SIZE, repeat;
	int nosect = 0;
	char fmtchar, fmtstr[64];
	unsigned long addr;
	unsigned long word;
	long offset = 0;
	int symbolic = 0;
	int valid = 0;
	int phys = 0;

	kdbgetintenv("MDCOUNT", &mdcount);
	kdbgetintenv("RADIX", &radix);
	kdbgetintenv("BYTESPERWORD", &bytesperword);

	/* Assume 'md <addr>' and start with environment values */
	repeat = mdcount * 16 / bytesperword;

	if (strcmp(argv[0], "mdr") == 0) {
		if (argc != 2)
			return KDB_ARGCOUNT;
		valid = 1;
	} else if (isdigit(argv[0][2])) {
		bytesperword = (int)(argv[0][2] - '0');
		if (bytesperword == 0) {
			bytesperword = last_bytesperword;
			if (bytesperword == 0)
				bytesperword = 4;
		}
		last_bytesperword = bytesperword;
		repeat = mdcount * 16 / bytesperword;
		if (!argv[0][3])
			valid = 1;
		else if (argv[0][3] == 'c' && argv[0][4]) {
			char *p;
			repeat = simple_strtoul(argv[0] + 4, &p, 10);
			mdcount = ((repeat * bytesperword) + 15) / 16;
			valid = !*p;
		}
		last_repeat = repeat;
	} else if (strcmp(argv[0], "md") == 0)
		valid = 1;
	else if (strcmp(argv[0], "mds") == 0)
		valid = 1;
	else if (strcmp(argv[0], "mdp") == 0) {
		phys = valid = 1;
	}
	if (!valid)
		return KDB_NOTFOUND;

	if (argc == 0) {
		if (last_addr == 0)
			return KDB_ARGCOUNT;
		addr = last_addr;
		radix = last_radix;
		bytesperword = last_bytesperword;
		repeat = last_repeat;
		mdcount = ((repeat * bytesperword) + 15) / 16;
	}

	if (argc) {
		unsigned long val;
		int diag, nextarg = 1;
		diag = kdbgetaddrarg(argc, argv, &nextarg, &addr,
				     &offset, NULL);
		if (diag)
			return diag;
		if (argc > nextarg+2)
			return KDB_ARGCOUNT;

		if (argc >= nextarg) {
			diag = kdbgetularg(argv[nextarg], &val);
			if (!diag) {
				mdcount = (int) val;
				repeat = mdcount * 16 / bytesperword;
			}
		}
		if (argc >= nextarg+1) {
			diag = kdbgetularg(argv[nextarg+1], &val);
			if (!diag)
				radix = (int) val;
		}
	}

	if (strcmp(argv[0], "mdr") == 0)
		return kdb_mdr(addr, mdcount);

	switch (radix) {
	case 10:
		fmtchar = 'd';
		break;
	case 16:
		fmtchar = 'x';
		break;
	case 8:
		fmtchar = 'o';
		break;
	default:
		return KDB_BADRADIX;
	}

	last_radix = radix;

	if (bytesperword > KDB_WORD_SIZE)
		return KDB_BADWIDTH;

	switch (bytesperword) {
	case 8:
		sprintf(fmtstr, "%%16.16l%c ", fmtchar);
		break;
	case 4:
		sprintf(fmtstr, "%%8.8l%c ", fmtchar);
		break;
	case 2:
		sprintf(fmtstr, "%%4.4l%c ", fmtchar);
		break;
	case 1:
		sprintf(fmtstr, "%%2.2l%c ", fmtchar);
		break;
	default:
		return KDB_BADWIDTH;
	}

	last_repeat = repeat;
	last_bytesperword = bytesperword;

	if (strcmp(argv[0], "mds") == 0) {
		symbolic = 1;
		/* Do not save these changes as last_*, they are temporary mds
		 * overrides.
		 */
		bytesperword = KDB_WORD_SIZE;
		repeat = mdcount;
		kdbgetintenv("NOSECT", &nosect);
	}

	/* Round address down modulo BYTESPERWORD */

	addr &= ~(bytesperword-1);

	while (repeat > 0) {
		unsigned long a;
		int n, z, num = (symbolic ? 1 : (16 / bytesperword));

		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;
		for (a = addr, z = 0; z < repeat; a += bytesperword, ++z) {
			if (phys) {
				if (kdb_getphysword(&word, a, bytesperword)
						|| word)
					break;
			} else if (kdb_getword(&word, a, bytesperword) || word)
				break;
		}
		n = min(num, repeat);
		kdb_md_line(fmtstr, addr, symbolic, nosect, bytesperword,
			    num, repeat, phys);
		addr += bytesperword * n;
		repeat -= n;
		z = (z + num - 1) / num;
		if (z > 2) {
			int s = num * (z-2);
			kdb_printf(kdb_machreg_fmt0 "-" kdb_machreg_fmt0
				   " zero suppressed\n",
				addr, addr + bytesperword * s - 1);
			addr += bytesperword * s;
			repeat -= s;
		}
	}
	last_addr = addr;

	return 0;
}

/*
 * kdb_mm - This function implements the 'mm' command.
 *	mm address-expression new-value
 * Remarks:
 *	mm works on machine words, mmW works on bytes.
 */
static int kdb_mm(int argc, const char **argv)
{
	int diag;
	unsigned long addr;
	long offset = 0;
	unsigned long contents;
	int nextarg;
	int width;

	if (argv[0][2] && !isdigit(argv[0][2]))
		return KDB_NOTFOUND;

	if (argc < 2)
		return KDB_ARGCOUNT;

	nextarg = 1;
	diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);
	if (diag)
		return diag;

	if (nextarg > argc)
		return KDB_ARGCOUNT;
	diag = kdbgetaddrarg(argc, argv, &nextarg, &contents, NULL, NULL);
	if (diag)
		return diag;

	if (nextarg != argc + 1)
		return KDB_ARGCOUNT;

	width = argv[0][2] ? (argv[0][2] - '0') : (KDB_WORD_SIZE);
	diag = kdb_putword(addr, contents, width);
	if (diag)
		return diag;

	kdb_printf(kdb_machreg_fmt " = " kdb_machreg_fmt "\n", addr, contents);

	return 0;
}

/*
 * kdb_go - This function implements the 'go' command.
 *	go [address-expression]
 */
static int kdb_go(int argc, const char **argv)
{
	unsigned long addr;
	int diag;
	int nextarg;
	long offset;

	if (raw_smp_processor_id() != kdb_initial_cpu) {
		kdb_printf("go must execute on the entry cpu, "
			   "please use \"cpu %d\" and then execute go\n",
			   kdb_initial_cpu);
		return KDB_BADCPUNUM;
	}
	if (argc == 1) {
		nextarg = 1;
		diag = kdbgetaddrarg(argc, argv, &nextarg,
				     &addr, &offset, NULL);
		if (diag)
			return diag;
	} else if (argc) {
		return KDB_ARGCOUNT;
	}

	diag = KDB_CMD_GO;
	if (KDB_FLAG(CATASTROPHIC)) {
		kdb_printf("Catastrophic error detected\n");
		kdb_printf("kdb_continue_catastrophic=%d, ",
			kdb_continue_catastrophic);
		if (kdb_continue_catastrophic == 0 && kdb_go_count++ == 0) {
			kdb_printf("type go a second time if you really want "
				   "to continue\n");
			return 0;
		}
		if (kdb_continue_catastrophic == 2) {
			kdb_printf("forcing reboot\n");
			kdb_reboot(0, NULL);
		}
		kdb_printf("attempting to continue\n");
	}
	return diag;
}

/*
 * kdb_rd - This function implements the 'rd' command.
 */
static int kdb_rd(int argc, const char **argv)
{
	int len = kdb_check_regs();
#if DBG_MAX_REG_NUM > 0
	int i;
	char *rname;
	int rsize;
	u64 reg64;
	u32 reg32;
	u16 reg16;
	u8 reg8;

	if (len)
		return len;

	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		rsize = dbg_reg_def[i].size * 2;
		if (rsize > 16)
			rsize = 2;
		if (len + strlen(dbg_reg_def[i].name) + 4 + rsize > 80) {
			len = 0;
			kdb_printf("\n");
		}
		if (len)
			len += kdb_printf("  ");
		switch(dbg_reg_def[i].size * 8) {
		case 8:
			rname = dbg_get_reg(i, &reg8, kdb_current_regs);
			if (!rname)
				break;
			len += kdb_printf("%s: %02x", rname, reg8);
			break;
		case 16:
			rname = dbg_get_reg(i, &reg16, kdb_current_regs);
			if (!rname)
				break;
			len += kdb_printf("%s: %04x", rname, reg16);
			break;
		case 32:
			rname = dbg_get_reg(i, &reg32, kdb_current_regs);
			if (!rname)
				break;
			len += kdb_printf("%s: %08x", rname, reg32);
			break;
		case 64:
			rname = dbg_get_reg(i, &reg64, kdb_current_regs);
			if (!rname)
				break;
			len += kdb_printf("%s: %016llx", rname, reg64);
			break;
		default:
			len += kdb_printf("%s: ??", dbg_reg_def[i].name);
		}
	}
	kdb_printf("\n");
#else
	if (len)
		return len;

	kdb_dumpregs(kdb_current_regs);
#endif
	return 0;
}

/*
 * kdb_rm - This function implements the 'rm' (register modify)  command.
 *	rm register-name new-contents
 * Remarks:
 *	Allows register modification with the same restrictions as gdb
 */
static int kdb_rm(int argc, const char **argv)
{
#if DBG_MAX_REG_NUM > 0
	int diag;
	const char *rname;
	int i;
	u64 reg64;
	u32 reg32;
	u16 reg16;
	u8 reg8;

	if (argc != 2)
		return KDB_ARGCOUNT;
	/*
	 * Allow presence or absence of leading '%' symbol.
	 */
	rname = argv[1];
	if (*rname == '%')
		rname++;

	diag = kdbgetu64arg(argv[2], &reg64);
	if (diag)
		return diag;

	diag = kdb_check_regs();
	if (diag)
		return diag;

	diag = KDB_BADREG;
	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		if (strcmp(rname, dbg_reg_def[i].name) == 0) {
			diag = 0;
			break;
		}
	}
	if (!diag) {
		switch(dbg_reg_def[i].size * 8) {
		case 8:
			reg8 = reg64;
			dbg_set_reg(i, &reg8, kdb_current_regs);
			break;
		case 16:
			reg16 = reg64;
			dbg_set_reg(i, &reg16, kdb_current_regs);
			break;
		case 32:
			reg32 = reg64;
			dbg_set_reg(i, &reg32, kdb_current_regs);
			break;
		case 64:
			dbg_set_reg(i, &reg64, kdb_current_regs);
			break;
		}
	}
	return diag;
#else
	kdb_printf("ERROR: Register set currently not implemented\n");
    return 0;
#endif
}

#if defined(CONFIG_MAGIC_SYSRQ)
/*
 * kdb_sr - This function implements the 'sr' (SYSRQ key) command
 *	which interfaces to the soi-disant MAGIC SYSRQ functionality.
 *		sr <magic-sysrq-code>
 */
static int kdb_sr(int argc, const char **argv)
{
	bool check_mask =
	    !kdb_check_flags(KDB_ENABLE_ALL, kdb_cmd_enabled, false);

	if (argc != 1)
		return KDB_ARGCOUNT;

	kdb_trap_printk++;
	__handle_sysrq(*argv[1], check_mask);
	kdb_trap_printk--;

	return 0;
}
#endif	/* CONFIG_MAGIC_SYSRQ */

/*
 * kdb_ef - This function implements the 'regs' (display exception
 *	frame) command.  This command takes an address and expects to
 *	find an exception frame at that address, formats and prints
 *	it.
 *		regs address-expression
 * Remarks:
 *	Not done yet.
 */
static int kdb_ef(int argc, const char **argv)
{
	int diag;
	unsigned long addr;
	long offset;
	int nextarg;

	if (argc != 1)
		return KDB_ARGCOUNT;

	nextarg = 1;
	diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);
	if (diag)
		return diag;
	show_regs((struct pt_regs *)addr);
	return 0;
}

#if defined(CONFIG_MODULES)
/*
 * kdb_lsmod - This function implements the 'lsmod' command.  Lists
 *	currently loaded kernel modules.
 *	Mostly taken from userland lsmod.
 */
static int kdb_lsmod(int argc, const char **argv)
{
	struct module *mod;

	if (argc != 0)
		return KDB_ARGCOUNT;

	kdb_printf("Module                  Size  modstruct     Used by\n");
	list_for_each_entry(mod, kdb_modules, list) {
		if (mod->state == MODULE_STATE_UNFORMED)
			continue;

		kdb_printf("%-20s%8u  0x%p ", mod->name,
			   mod->core_size, (void *)mod);
#ifdef CONFIG_MODULE_UNLOAD
		kdb_printf("%4ld ", module_refcount(mod));
#endif
		if (mod->state == MODULE_STATE_GOING)
			kdb_printf(" (Unloading)");
		else if (mod->state == MODULE_STATE_COMING)
			kdb_printf(" (Loading)");
		else
			kdb_printf(" (Live)");
		kdb_printf(" 0x%p", mod->module_core);

#ifdef CONFIG_MODULE_UNLOAD
		{
			struct module_use *use;
			kdb_printf(" [ ");
			list_for_each_entry(use, &mod->source_list,
					    source_list)
				kdb_printf("%s ", use->target->name);
			kdb_printf("]\n");
		}
#endif
	}

	return 0;
}

#endif	/* CONFIG_MODULES */

/*
 * kdb_env - This function implements the 'env' command.  Display the
 *	current environment variables.
 */

static int kdb_env(int argc, const char **argv)
{
	int i;

	for (i = 0; i < __nenv; i++) {
		if (__env[i])
			kdb_printf("%s\n", __env[i]);
	}

	if (KDB_DEBUG(MASK))
		kdb_printf("KDBFLAGS=0x%x\n", kdb_flags);

	return 0;
}

#ifdef CONFIG_PRINTK
/*
 * kdb_dmesg - This function implements the 'dmesg' command to display
 *	the contents of the syslog buffer.
 *		dmesg [lines] [adjust]
 */
static int kdb_dmesg(int argc, const char **argv)
{
	int diag;
	int logging;
	int lines = 0;
	int adjust = 0;
	int n = 0;
	int skip = 0;
	struct kmsg_dumper dumper = { .active = 1 };
	size_t len;
	char buf[201];

	if (argc > 2)
		return KDB_ARGCOUNT;
	if (argc) {
		char *cp;
		lines = simple_strtol(argv[1], &cp, 0);
		if (*cp)
			lines = 0;
		if (argc > 1) {
			adjust = simple_strtoul(argv[2], &cp, 0);
			if (*cp || adjust < 0)
				adjust = 0;
		}
	}

	/* disable LOGGING if set */
	diag = kdbgetintenv("LOGGING", &logging);
	if (!diag && logging) {
		const char *setargs[] = { "set", "LOGGING", "0" };
		kdb_set(2, setargs);
	}

	kmsg_dump_rewind_nolock(&dumper);
	while (kmsg_dump_get_line_nolock(&dumper, 1, NULL, 0, NULL))
		n++;

	if (lines < 0) {
		if (adjust >= n)
			kdb_printf("buffer only contains %d lines, nothing "
				   "printed\n", n);
		else if (adjust - lines >= n)
			kdb_printf("buffer only contains %d lines, last %d "
				   "lines printed\n", n, n - adjust);
		skip = adjust;
		lines = abs(lines);
	} else if (lines > 0) {
		skip = n - lines - adjust;
		lines = abs(lines);
		if (adjust >= n) {
			kdb_printf("buffer only contains %d lines, "
				   "nothing printed\n", n);
			skip = n;
		} else if (skip < 0) {
			lines += skip;
			skip = 0;
			kdb_printf("buffer only contains %d lines, first "
				   "%d lines printed\n", n, lines);
		}
	} else {
		lines = n;
	}

	if (skip >= n || skip < 0)
		return 0;

	kmsg_dump_rewind_nolock(&dumper);
	while (kmsg_dump_get_line_nolock(&dumper, 1, buf, sizeof(buf), &len)) {
		if (skip) {
			skip--;
			continue;
		}
		if (!lines--)
			break;
		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;

		kdb_printf("%.*s\n", (int)len - 1, buf);
	}

	return 0;
}
#endif /* CONFIG_PRINTK */

/* Make sure we balance enable/disable calls, must disable first. */
static atomic_t kdb_nmi_disabled;

static int kdb_disable_nmi(int argc, const char *argv[])
{
	if (atomic_read(&kdb_nmi_disabled))
		return 0;
	atomic_set(&kdb_nmi_disabled, 1);
	arch_kgdb_ops.enable_nmi(0);
	return 0;
}

static int kdb_param_enable_nmi(const char *val, const struct kernel_param *kp)
{
	if (!atomic_add_unless(&kdb_nmi_disabled, -1, 0))
		return -EINVAL;
	arch_kgdb_ops.enable_nmi(1);
	return 0;
}

static const struct kernel_param_ops kdb_param_ops_enable_nmi = {
	.set = kdb_param_enable_nmi,
};
module_param_cb(enable_nmi, &kdb_param_ops_enable_nmi, NULL, 0600);

/*
 * kdb_cpu - This function implements the 'cpu' command.
 *	cpu	[<cpunum>]
 * Returns:
 *	KDB_CMD_CPU for success, a kdb diagnostic if error
 */
static void kdb_cpu_status(void)
{
	int i, start_cpu, first_print = 1;
	char state, prev_state = '?';

	kdb_printf("Currently on cpu %d\n", raw_smp_processor_id());
	kdb_printf("Available cpus: ");
	for (start_cpu = -1, i = 0; i < NR_CPUS; i++) {
		if (!cpu_online(i)) {
			state = 'F';	/* cpu is offline */
		} else if (!kgdb_info[i].enter_kgdb) {
			state = 'D';	/* cpu is online but unresponsive */
		} else {
			state = ' ';	/* cpu is responding to kdb */
			if (kdb_task_state_char(KDB_TSK(i)) == 'I')
				state = 'I';	/* idle task */
		}
		if (state != prev_state) {
			if (prev_state != '?') {
				if (!first_print)
					kdb_printf(", ");
				first_print = 0;
				kdb_printf("%d", start_cpu);
				if (start_cpu < i-1)
					kdb_printf("-%d", i-1);
				if (prev_state != ' ')
					kdb_printf("(%c)", prev_state);
			}
			prev_state = state;
			start_cpu = i;
		}
	}
	/* print the trailing cpus, ignoring them if they are all offline */
	if (prev_state != 'F') {
		if (!first_print)
			kdb_printf(", ");
		kdb_printf("%d", start_cpu);
		if (start_cpu < i-1)
			kdb_printf("-%d", i-1);
		if (prev_state != ' ')
			kdb_printf("(%c)", prev_state);
	}
	kdb_printf("\n");
}

static int kdb_cpu(int argc, const char **argv)
{
	unsigned long cpunum;
	int diag;

	if (argc == 0) {
		kdb_cpu_status();
		return 0;
	}

	if (argc != 1)
		return KDB_ARGCOUNT;

	diag = kdbgetularg(argv[1], &cpunum);
	if (diag)
		return diag;

	/*
	 * Validate cpunum
	 */
	if ((cpunum > NR_CPUS) || !kgdb_info[cpunum].enter_kgdb)
		return KDB_BADCPUNUM;

	dbg_switch_cpu = cpunum;

	/*
	 * Switch to other cpu
	 */
	return KDB_CMD_CPU;
}

/* The user may not realize that ps/bta with no parameters does not print idle
 * or sleeping system daemon processes, so tell them how many were suppressed.
 */
void kdb_ps_suppressed(void)
{
	int idle = 0, daemon = 0;
	unsigned long mask_I = kdb_task_state_string("I"),
		      mask_M = kdb_task_state_string("M");
	unsigned long cpu;
	const struct task_struct *p, *g;
	for_each_online_cpu(cpu) {
		p = kdb_curr_task(cpu);
		if (kdb_task_state(p, mask_I))
			++idle;
	}
	kdb_do_each_thread(g, p) {
		if (kdb_task_state(p, mask_M))
			++daemon;
	} kdb_while_each_thread(g, p);
	if (idle || daemon) {
		if (idle)
			kdb_printf("%d idle process%s (state I)%s\n",
				   idle, idle == 1 ? "" : "es",
				   daemon ? " and " : "");
		if (daemon)
			kdb_printf("%d sleeping system daemon (state M) "
				   "process%s", daemon,
				   daemon == 1 ? "" : "es");
		kdb_printf(" suppressed,\nuse 'ps A' to see all.\n");
	}
}

/*
 * kdb_ps - This function implements the 'ps' command which shows a
 *	list of the active processes.
 *		ps [DRSTCZEUIMA]   All processes, optionally filtered by state
 */
void kdb_ps1(const struct task_struct *p)
{
	int cpu;
	unsigned long tmp;

	if (!p || probe_kernel_read(&tmp, (char *)p, sizeof(unsigned long)))
		return;

	cpu = kdb_process_cpu(p);
	kdb_printf("0x%p %8d %8d  %d %4d   %c  0x%p %c%s\n",
		   (void *)p, p->pid, p->parent->pid,
		   kdb_task_has_cpu(p), kdb_process_cpu(p),
		   kdb_task_state_char(p),
		   (void *)(&p->thread),
		   p == kdb_curr_task(raw_smp_processor_id()) ? '*' : ' ',
		   p->comm);
	if (kdb_task_has_cpu(p)) {
		if (!KDB_TSK(cpu)) {
			kdb_printf("  Error: no saved data for this cpu\n");
		} else {
			if (KDB_TSK(cpu) != p)
				kdb_printf("  Error: does not match running "
				   "process table (0x%p)\n", KDB_TSK(cpu));
		}
	}
}

static int kdb_ps(int argc, const char **argv)
{
	struct task_struct *g, *p;
	unsigned long mask, cpu;

	if (argc == 0)
		kdb_ps_suppressed();
	kdb_printf("%-*s      Pid   Parent [*] cpu State %-*s Command\n",
		(int)(2*sizeof(void *))+2, "Task Addr",
		(int)(2*sizeof(void *))+2, "Thread");
	mask = kdb_task_state_string(argc ? argv[1] : NULL);
	/* Run the active tasks first */
	for_each_online_cpu(cpu) {
		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;
		p = kdb_curr_task(cpu);
		if (kdb_task_state(p, mask))
			kdb_ps1(p);
	}
	kdb_printf("\n");
	/* Now the real tasks */
	kdb_do_each_thread(g, p) {
		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;
		if (kdb_task_state(p, mask))
			kdb_ps1(p);
	} kdb_while_each_thread(g, p);

	return 0;
}

/*
 * kdb_pid - This function implements the 'pid' command which switches
 *	the currently active process.
 *		pid [<pid> | R]
 */
static int kdb_pid(int argc, const char **argv)
{
	struct task_struct *p;
	unsigned long val;
	int diag;

	if (argc > 1)
		return KDB_ARGCOUNT;

	if (argc) {
		if (strcmp(argv[1], "R") == 0) {
			p = KDB_TSK(kdb_initial_cpu);
		} else {
			diag = kdbgetularg(argv[1], &val);
			if (diag)
				return KDB_BADINT;

			p = find_task_by_pid_ns((pid_t)val,	&init_pid_ns);
			if (!p) {
				kdb_printf("No task with pid=%d\n", (pid_t)val);
				return 0;
			}
		}
		kdb_set_current_task(p);
	}
	kdb_printf("KDB current process is %s(pid=%d)\n",
		   kdb_current_task->comm,
		   kdb_current_task->pid);

	return 0;
}

static int kdb_kgdb(int argc, const char **argv)
{
	return KDB_CMD_KGDB;
}

/*
 * kdb_help - This function implements the 'help' and '?' commands.
 */
static int kdb_help(int argc, const char **argv)
{
	kdbtab_t *kt;
	int i;

	kdb_printf("%-15.15s %-20.20s %s\n", "Command", "Usage", "Description");
	kdb_printf("-----------------------------"
		   "-----------------------------\n");
	for_each_kdbcmd(kt, i) {
		char *space = "";
		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;
		if (!kt->cmd_name)
			continue;
		if (!kdb_check_flags(kt->cmd_flags, kdb_cmd_enabled, true))
			continue;
		if (strlen(kt->cmd_usage) > 20)
			space = "\n                                    ";
		kdb_printf("%-15.15s %-20s%s%s\n", kt->cmd_name,
			   kt->cmd_usage, space, kt->cmd_help);
	}
	return 0;
}

/*
 * kdb_kill - This function implements the 'kill' commands.
 */
static int kdb_kill(int argc, const char **argv)
{
	long sig, pid;
	char *endp;
	struct task_struct *p;
	struct siginfo info;

	if (argc != 2)
		return KDB_ARGCOUNT;

	sig = simple_strtol(argv[1], &endp, 0);
	if (*endp)
		return KDB_BADINT;
	if (sig >= 0) {
		kdb_printf("Invalid signal parameter.<-signal>\n");
		return 0;
	}
	sig = -sig;

	pid = simple_strtol(argv[2], &endp, 0);
	if (*endp)
		return KDB_BADINT;
	if (pid <= 0) {
		kdb_printf("Process ID must be large than 0.\n");
		return 0;
	}

	/* Find the process. */
	p = find_task_by_pid_ns(pid, &init_pid_ns);
	if (!p) {
		kdb_printf("The specified process isn't found.\n");
		return 0;
	}
	p = p->group_leader;
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = pid;  /* same capabilities as process being signalled */
	info.si_uid = 0;    /* kdb has root authority */
	kdb_send_sig_info(p, &info);
	return 0;
}

struct kdb_tm {
	int tm_sec;	/* seconds */
	int tm_min;	/* minutes */
	int tm_hour;	/* hours */
	int tm_mday;	/* day of the month */
	int tm_mon;	/* month */
	int tm_year;	/* year */
};

static void kdb_gmtime(struct timespec *tv, struct kdb_tm *tm)
{
	/* This will work from 1970-2099, 2100 is not a leap year */
	static int mon_day[] = { 31, 29, 31, 30, 31, 30, 31,
				 31, 30, 31, 30, 31 };
	memset(tm, 0, sizeof(*tm));
	tm->tm_sec  = tv->tv_sec % (24 * 60 * 60);
	tm->tm_mday = tv->tv_sec / (24 * 60 * 60) +
		(2 * 365 + 1); /* shift base from 1970 to 1968 */
	tm->tm_min =  tm->tm_sec / 60 % 60;
	tm->tm_hour = tm->tm_sec / 60 / 60;
	tm->tm_sec =  tm->tm_sec % 60;
	tm->tm_year = 68 + 4*(tm->tm_mday / (4*365+1));
	tm->tm_mday %= (4*365+1);
	mon_day[1] = 29;
	while (tm->tm_mday >= mon_day[tm->tm_mon]) {
		tm->tm_mday -= mon_day[tm->tm_mon];
		if (++tm->tm_mon == 12) {
			tm->tm_mon = 0;
			++tm->tm_year;
			mon_day[1] = 28;
		}
	}
	++tm->tm_mday;
}

/*
 * Most of this code has been lifted from kernel/timer.c::sys_sysinfo().
 * I cannot call that code directly from kdb, it has an unconditional
 * cli()/sti() and calls routines that take locks which can stop the debugger.
 */
static void kdb_sysinfo(struct sysinfo *val)
{
	struct timespec uptime;
	ktime_get_ts(&uptime);
	memset(val, 0, sizeof(*val));
	val->uptime = uptime.tv_sec;
	val->loads[0] = avenrun[0];
	val->loads[1] = avenrun[1];
	val->loads[2] = avenrun[2];
	val->procs = nr_threads-1;
	si_meminfo(val);

	return;
}

/*
 * kdb_summary - This function implements the 'summary' command.
 */
static int kdb_summary(int argc, const char **argv)
{
	struct timespec now;
	struct kdb_tm tm;
	struct sysinfo val;

	if (argc)
		return KDB_ARGCOUNT;

	kdb_printf("sysname    %s\n", init_uts_ns.name.sysname);
	kdb_printf("release    %s\n", init_uts_ns.name.release);
	kdb_printf("version    %s\n", init_uts_ns.name.version);
	kdb_printf("machine    %s\n", init_uts_ns.name.machine);
	kdb_printf("nodename   %s\n", init_uts_ns.name.nodename);
	kdb_printf("domainname %s\n", init_uts_ns.name.domainname);
	kdb_printf("ccversion  %s\n", __stringify(CCVERSION));

	now = __current_kernel_time();
	kdb_gmtime(&now, &tm);
	kdb_printf("date       %04d-%02d-%02d %02d:%02d:%02d "
		   "tz_minuteswest %d\n",
		1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		sys_tz.tz_minuteswest);

	kdb_sysinfo(&val);
	kdb_printf("uptime     ");
	if (val.uptime > (24*60*60)) {
		int days = val.uptime / (24*60*60);
		val.uptime %= (24*60*60);
		kdb_printf("%d day%s ", days, days == 1 ? "" : "s");
	}
	kdb_printf("%02ld:%02ld\n", val.uptime/(60*60), (val.uptime/60)%60);

	/* lifted from fs/proc/proc_misc.c::loadavg_read_proc() */

#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)
	kdb_printf("load avg   %ld.%02ld %ld.%02ld %ld.%02ld\n",
		LOAD_INT(val.loads[0]), LOAD_FRAC(val.loads[0]),
		LOAD_INT(val.loads[1]), LOAD_FRAC(val.loads[1]),
		LOAD_INT(val.loads[2]), LOAD_FRAC(val.loads[2]));
#undef LOAD_INT
#undef LOAD_FRAC
	/* Display in kilobytes */
#define K(x) ((x) << (PAGE_SHIFT - 10))
	kdb_printf("\nMemTotal:       %8lu kB\nMemFree:        %8lu kB\n"
		   "Buffers:        %8lu kB\n",
		   val.totalram, val.freeram, val.bufferram);
	return 0;
}

/*
 * kdb_per_cpu - This function implements the 'per_cpu' command.
 */
static int kdb_per_cpu(int argc, const char **argv)
{
	char fmtstr[64];
	int cpu, diag, nextarg = 1;
	unsigned long addr, symaddr, val, bytesperword = 0, whichcpu = ~0UL;

	if (argc < 1 || argc > 3)
		return KDB_ARGCOUNT;

	diag = kdbgetaddrarg(argc, argv, &nextarg, &symaddr, NULL, NULL);
	if (diag)
		return diag;

	if (argc >= 2) {
		diag = kdbgetularg(argv[2], &bytesperword);
		if (diag)
			return diag;
	}
	if (!bytesperword)
		bytesperword = KDB_WORD_SIZE;
	else if (bytesperword > KDB_WORD_SIZE)
		return KDB_BADWIDTH;
	sprintf(fmtstr, "%%0%dlx ", (int)(2*bytesperword));
	if (argc >= 3) {
		diag = kdbgetularg(argv[3], &whichcpu);
		if (diag)
			return diag;
		if (!cpu_online(whichcpu)) {
			kdb_printf("cpu %ld is not online\n", whichcpu);
			return KDB_BADCPUNUM;
		}
	}

	/* Most architectures use __per_cpu_offset[cpu], some use
	 * __per_cpu_offset(cpu), smp has no __per_cpu_offset.
	 */
#ifdef	__per_cpu_offset
#define KDB_PCU(cpu) __per_cpu_offset(cpu)
#else
#ifdef	CONFIG_SMP
#define KDB_PCU(cpu) __per_cpu_offset[cpu]
#else
#define KDB_PCU(cpu) 0
#endif
#endif
	for_each_online_cpu(cpu) {
		if (KDB_FLAG(CMD_INTERRUPT))
			return 0;

		if (whichcpu != ~0UL && whichcpu != cpu)
			continue;
		addr = symaddr + KDB_PCU(cpu);
		diag = kdb_getword(&val, addr, bytesperword);
		if (diag) {
			kdb_printf("%5d " kdb_bfd_vma_fmt0 " - unable to "
				   "read, diag=%d\n", cpu, addr, diag);
			continue;
		}
		kdb_printf("%5d ", cpu);
		kdb_md_line(fmtstr, addr,
			bytesperword == KDB_WORD_SIZE,
			1, bytesperword, 1, 1, 0);
	}
#undef KDB_PCU
	return 0;
}

/*
 * display help for the use of cmd | grep pattern
 */
static int kdb_grep_help(int argc, const char **argv)
{
	kdb_printf("Usage of  cmd args | grep pattern:\n");
	kdb_printf("  Any command's output may be filtered through an ");
	kdb_printf("emulated 'pipe'.\n");
	kdb_printf("  'grep' is just a key word.\n");
	kdb_printf("  The pattern may include a very limited set of "
		   "metacharacters:\n");
	kdb_printf("   pattern or ^pattern or pattern$ or ^pattern$\n");
	kdb_printf("  And if there are spaces in the pattern, you may "
		   "quote it:\n");
	kdb_printf("   \"pat tern\" or \"^pat tern\" or \"pat tern$\""
		   " or \"^pat tern$\"\n");
	return 0;
}

/*
 * kdb_register_flags - This function is used to register a kernel
 * 	debugger command.
 * Inputs:
 *	cmd	Command name
 *	func	Function to execute the command
 *	usage	A simple usage string showing arguments
 *	help	A simple help string describing command
 *	repeat	Does the command auto repeat on enter?
 * Returns:
 *	zero for success, one if a duplicate command.
 */
#define kdb_command_extend 50	/* arbitrary */
int kdb_register_flags(char *cmd,
		       kdb_func_t func,
		       char *usage,
		       char *help,
		       short minlen,
		       kdb_cmdflags_t flags)
{
	int i;
	kdbtab_t *kp;

	/*
	 *  Brute force method to determine duplicates
	 */
	for_each_kdbcmd(kp, i) {
		if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {
			kdb_printf("Duplicate kdb command registered: "
				"%s, func %p help %s\n", cmd, func, help);
			return 1;
		}
	}

	/*
	 * Insert command into first available location in table
	 */
	for_each_kdbcmd(kp, i) {
		if (kp->cmd_name == NULL)
			break;
	}

	if (i >= kdb_max_commands) {
		kdbtab_t *new = kmalloc((kdb_max_commands - KDB_BASE_CMD_MAX +
			 kdb_command_extend) * sizeof(*new), GFP_KDB);
		if (!new) {
			kdb_printf("Could not allocate new kdb_command "
				   "table\n");
			return 1;
		}
		if (kdb_commands) {
			memcpy(new, kdb_commands,
			  (kdb_max_commands - KDB_BASE_CMD_MAX) * sizeof(*new));
			kfree(kdb_commands);
		}
		memset(new + kdb_max_commands - KDB_BASE_CMD_MAX, 0,
		       kdb_command_extend * sizeof(*new));
		kdb_commands = new;
		kp = kdb_commands + kdb_max_commands - KDB_BASE_CMD_MAX;
		kdb_max_commands += kdb_command_extend;
	}

	kp->cmd_name   = cmd;
	kp->cmd_func   = func;
	kp->cmd_usage  = usage;
	kp->cmd_help   = help;
	kp->cmd_minlen = minlen;
	kp->cmd_flags  = flags;

	return 0;
}
EXPORT_SYMBOL_GPL(kdb_register_flags);


/*
 * kdb_register - Compatibility register function for commands that do
 *	not need to specify a repeat state.  Equivalent to
 *	kdb_register_flags with flags set to 0.
 * Inputs:
 *	cmd	Command name
 *	func	Function to execute the command
 *	usage	A simple usage string showing arguments
 *	help	A simple help string describing command
 * Returns:
 *	zero for success, one if a duplicate command.
 */
int kdb_register(char *cmd,
	     kdb_func_t func,
	     char *usage,
	     char *help,
	     short minlen)
{
	return kdb_register_flags(cmd, func, usage, help, minlen, 0);
}
EXPORT_SYMBOL_GPL(kdb_register);

/*
 * kdb_unregister - This function is used to unregister a kernel
 *	debugger command.  It is generally called when a module which
 *	implements kdb commands is unloaded.
 * Inputs:
 *	cmd	Command name
 * Returns:
 *	zero for success, one command not registered.
 */
int kdb_unregister(char *cmd)
{
	int i;
	kdbtab_t *kp;

	/*
	 *  find the command.
	 */
	for_each_kdbcmd(kp, i) {
		if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {
			kp->cmd_name = NULL;
			return 0;
		}
	}

	/* Couldn't find it.  */
	return 1;
}
EXPORT_SYMBOL_GPL(kdb_unregister);

/* Initialize the kdb command table. */
static void __init kdb_inittab(void)
{
	int i;
	kdbtab_t *kp;

	for_each_kdbcmd(kp, i)
		kp->cmd_name = NULL;

	kdb_register_flags("md", kdb_md, "<vaddr>",
	  "Display Memory Contents, also mdWcN, e.g. md8c1", 1,
	  KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
	kdb_register_flags("mdr", kdb_md, "<vaddr> <bytes>",
	  "Display Raw Memory", 0,
	  KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
	kdb_register_flags("mdp", kdb_md, "<paddr> <bytes>",
	  "Display Physical Memory", 0,
	  KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
	kdb_register_flags("mds", kdb_md, "<vaddr>",
	  "Display Memory Symbolically", 0,
	  KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
	kdb_register_flags("mm", kdb_mm, "<vaddr> <contents>",
	  "Modify Memory Contents", 0,
	  KDB_ENABLE_MEM_WRITE | KDB_REPEAT_NO_ARGS);
	kdb_register_flags("go", kdb_go, "[<vaddr>]",
	  "Continue Execution", 1,
	  KDB_ENABLE_REG_WRITE | KDB_ENABLE_ALWAYS_SAFE_NO_ARGS);
	kdb_register_flags("rd", kdb_rd, "",
	  "Display Registers", 0,
	  KDB_ENABLE_REG_READ);
	kdb_register_flags("rm", kdb_rm, "<reg> <contents>",
	  "Modify Registers", 0,
	  KDB_ENABLE_REG_WRITE);
	kdb_register_flags("ef", kdb_ef, "<vaddr>",
	  "Display exception frame", 0,
	  KDB_ENABLE_MEM_READ);
	kdb_register_flags("bt", kdb_bt, "[<vaddr>]",
	  "Stack traceback", 1,
	  KDB_ENABLE_MEM_READ | KDB_ENABLE_INSPECT_NO_ARGS);
	kdb_register_flags("btp", kdb_bt, "<pid>",
	  "Display stack for process <pid>", 0,
	  KDB_ENABLE_INSPECT);
	kdb_register_flags("bta", kdb_bt, "[D|R|S|T|C|Z|E|U|I|M|A]",
	  "Backtrace all processes matching state flag", 0,
	  KDB_ENABLE_INSPECT);
	kdb_register_flags("btc", kdb_bt, "",
	  "Backtrace current process on each cpu", 0,
	  KDB_ENABLE_INSPECT);
	kdb_register_flags("btt", kdb_bt, "<vaddr>",
	  "Backtrace process given its struct task address", 0,
	  KDB_ENABLE_MEM_READ | KDB_ENABLE_INSPECT_NO_ARGS);
	kdb_register_flags("env", kdb_env, "",
	  "Show environment variables", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("set", kdb_set, "",
	  "Set environment variables", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("help", kdb_help, "",
	  "Display Help Message", 1,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("?", kdb_help, "",
	  "Display Help Message", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("cpu", kdb_cpu, "<cpunum>",
	  "Switch to new cpu", 0,
	  KDB_ENABLE_ALWAYS_SAFE_NO_ARGS);
	kdb_register_flags("kgdb", kdb_kgdb, "",
	  "Enter kgdb mode", 0, 0);
	kdb_register_flags("ps", kdb_ps, "[<flags>|A]",
	  "Display active task list", 0,
	  KDB_ENABLE_INSPECT);
	kdb_register_flags("pid", kdb_pid, "<pidnum>",
	  "Switch to another task", 0,
	  KDB_ENABLE_INSPECT);
	kdb_register_flags("reboot", kdb_reboot, "",
	  "Reboot the machine immediately", 0,
	  KDB_ENABLE_REBOOT);
#if defined(CONFIG_MODULES)
	kdb_register_flags("lsmod", kdb_lsmod, "",
	  "List loaded kernel modules", 0,
	  KDB_ENABLE_INSPECT);
#endif
#if defined(CONFIG_MAGIC_SYSRQ)
	kdb_register_flags("sr", kdb_sr, "<key>",
	  "Magic SysRq key", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
#endif
#if defined(CONFIG_PRINTK)
	kdb_register_flags("dmesg", kdb_dmesg, "[lines]",
	  "Display syslog buffer", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
#endif
	if (arch_kgdb_ops.enable_nmi) {
		kdb_register_flags("disable_nmi", kdb_disable_nmi, "",
		  "Disable NMI entry to KDB", 0,
		  KDB_ENABLE_ALWAYS_SAFE);
	}
	kdb_register_flags("defcmd", kdb_defcmd, "name \"usage\" \"help\"",
	  "Define a set of commands, down to endefcmd", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("kill", kdb_kill, "<-signal> <pid>",
	  "Send a signal to a process", 0,
	  KDB_ENABLE_SIGNAL);
	kdb_register_flags("summary", kdb_summary, "",
	  "Summarize the system", 4,
	  KDB_ENABLE_ALWAYS_SAFE);
	kdb_register_flags("per_cpu", kdb_per_cpu, "<sym> [<bytes>] [<cpu>]",
	  "Display per_cpu variables", 3,
	  KDB_ENABLE_MEM_READ);
	kdb_register_flags("grephelp", kdb_grep_help, "",
	  "Display help on | grep", 0,
	  KDB_ENABLE_ALWAYS_SAFE);
}

/* Execute any commands defined in kdb_cmds.  */
static void __init kdb_cmd_init(void)
{
	int i, diag;
	for (i = 0; kdb_cmds[i]; ++i) {
		diag = kdb_parse(kdb_cmds[i]);
		if (diag)
			kdb_printf("kdb command %s failed, kdb diag %d\n",
				kdb_cmds[i], diag);
	}
	if (defcmd_in_progress) {
		kdb_printf("Incomplete 'defcmd' set, forcing endefcmd\n");
		kdb_parse("endefcmd");
	}
}

/* Initialize kdb_printf, breakpoint tables and kdb state */
void __init kdb_init(int lvl)
{
	static int kdb_init_lvl = KDB_NOT_INITIALIZED;
	int i;

	if (kdb_init_lvl == KDB_INIT_FULL || lvl <= kdb_init_lvl)
		return;
	for (i = kdb_init_lvl; i < lvl; i++) {
		switch (i) {
		case KDB_NOT_INITIALIZED:
			kdb_inittab();		/* Initialize Command Table */
			kdb_initbptab();	/* Initialize Breakpoints */
			break;
		case KDB_INIT_EARLY:
			kdb_cmd_init();		/* Build kdb_cmds tables */
			break;
		}
	}
	kdb_init_lvl = lvl;
}

static int validate_change(struct cpuset *cur, struct cpuset *trial)
{
	struct cgroup_subsys_state *css;
	struct cpuset *c, *par;
	int ret;

	rcu_read_lock();

	/* Each of our child cpusets must be a subset of us */
	ret = -EBUSY;
	cpuset_for_each_child(c, css, cur)
		if (!is_cpuset_subset(c, trial))
			goto out;

	/* Remaining checks don't apply to root cpuset */
	ret = 0;
	if (cur == &top_cpuset)
		goto out;

	par = parent_cs(cur);

	/* On legacy hiearchy, we must be a subset of our parent cpuset. */
	ret = -EACCES;
	if (!cgroup_on_dfl(cur->css.cgroup) && !is_cpuset_subset(trial, par))
		goto out;

	/*
	 * If either I or some sibling (!= me) is exclusive, we can't
	 * overlap
	 */
	ret = -EINVAL;
	cpuset_for_each_child(c, css, par) {
		if ((is_cpu_exclusive(trial) || is_cpu_exclusive(c)) &&
		    c != cur &&
		    cpumask_intersects(trial->cpus_allowed, c->cpus_allowed))
			goto out;
		if ((is_mem_exclusive(trial) || is_mem_exclusive(c)) &&
		    c != cur &&
		    nodes_intersects(trial->mems_allowed, c->mems_allowed))
			goto out;
	}

	/*
	 * Cpusets with tasks - existing or newly being attached - can't
	 * be changed to have empty cpus_allowed or mems_allowed.
	 */
	ret = -ENOSPC;
	if ((cgroup_has_tasks(cur->css.cgroup) || cur->attach_in_progress)) {
		if (!cpumask_empty(cur->cpus_allowed) &&
		    cpumask_empty(trial->cpus_allowed))
			goto out;
		if (!nodes_empty(cur->mems_allowed) &&
		    nodes_empty(trial->mems_allowed))
			goto out;
	}

	/*
	 * We can't shrink if we won't have enough room for SCHED_DEADLINE
	 * tasks.
	 */
	ret = -EBUSY;
	if (is_cpu_exclusive(cur) &&
	    !cpuset_cpumask_can_shrink(cur->cpus_allowed,
				       trial->cpus_allowed))
		goto out;

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

static int cpuset_css_online(struct cgroup_subsys_state *css)
{
	struct cpuset *cs = css_cs(css);
	struct cpuset *parent = parent_cs(cs);
	struct cpuset *tmp_cs;
	struct cgroup_subsys_state *pos_css;

	if (!parent)
		return 0;

	mutex_lock(&cpuset_mutex);

	set_bit(CS_ONLINE, &cs->flags);
	if (is_spread_page(parent))
		set_bit(CS_SPREAD_PAGE, &cs->flags);
	if (is_spread_slab(parent))
		set_bit(CS_SPREAD_SLAB, &cs->flags);

	cpuset_inc();

	spin_lock_irq(&callback_lock);
	if (cgroup_on_dfl(cs->css.cgroup)) {
		cpumask_copy(cs->effective_cpus, parent->effective_cpus);
		cs->effective_mems = parent->effective_mems;
	}
	spin_unlock_irq(&callback_lock);

	if (!test_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags))
		goto out_unlock;

	/*
	 * Clone @parent's configuration if CGRP_CPUSET_CLONE_CHILDREN is
	 * set.  This flag handling is implemented in cgroup core for
	 * histrical reasons - the flag may be specified during mount.
	 *
	 * Currently, if any sibling cpusets have exclusive cpus or mem, we
	 * refuse to clone the configuration - thereby refusing the task to
	 * be entered, and as a result refusing the sys_unshare() or
	 * clone() which initiated it.  If this becomes a problem for some
	 * users who wish to allow that scenario, then this could be
	 * changed to grant parent->cpus_allowed-sibling_cpus_exclusive
	 * (and likewise for mems) to the new cgroup.
	 */
	rcu_read_lock();
	cpuset_for_each_child(tmp_cs, pos_css, parent) {
		if (is_mem_exclusive(tmp_cs) || is_cpu_exclusive(tmp_cs)) {
			rcu_read_unlock();
			goto out_unlock;
		}
	}
	rcu_read_unlock();

	spin_lock_irq(&callback_lock);
	cs->mems_allowed = parent->mems_allowed;
	cpumask_copy(cs->cpus_allowed, parent->cpus_allowed);
	spin_unlock_irq(&callback_lock);
out_unlock:
	mutex_unlock(&cpuset_mutex);
	return 0;
}

static void cpuset_hotplug_workfn(struct work_struct *work)
{
	static cpumask_t new_cpus;
	static nodemask_t new_mems;
	bool cpus_updated, mems_updated;
	bool on_dfl = cgroup_on_dfl(top_cpuset.css.cgroup);

	mutex_lock(&cpuset_mutex);

	/* fetch the available cpus/mems and find out which changed how */
	cpumask_copy(&new_cpus, cpu_active_mask);
	new_mems = node_states[N_MEMORY];

	cpus_updated = !cpumask_equal(top_cpuset.effective_cpus, &new_cpus);
	mems_updated = !nodes_equal(top_cpuset.effective_mems, new_mems);

	/* synchronize cpus_allowed to cpu_active_mask */
	if (cpus_updated) {
		spin_lock_irq(&callback_lock);
		if (!on_dfl)
			cpumask_copy(top_cpuset.cpus_allowed, &new_cpus);
		cpumask_copy(top_cpuset.effective_cpus, &new_cpus);
		spin_unlock_irq(&callback_lock);
		/* we don't mess with cpumasks of tasks in top_cpuset */
	}

	/* synchronize mems_allowed to N_MEMORY */
	if (mems_updated) {
		spin_lock_irq(&callback_lock);
		if (!on_dfl)
			top_cpuset.mems_allowed = new_mems;
		top_cpuset.effective_mems = new_mems;
		spin_unlock_irq(&callback_lock);
		update_tasks_nodemask(&top_cpuset);
	}

	mutex_unlock(&cpuset_mutex);

	/* if cpus or mems changed, we need to propagate to descendants */
	if (cpus_updated || mems_updated) {
		struct cpuset *cs;
		struct cgroup_subsys_state *pos_css;

		rcu_read_lock();
		cpuset_for_each_descendant_pre(cs, pos_css, &top_cpuset) {
			if (cs == &top_cpuset || !css_tryget_online(&cs->css))
				continue;
			rcu_read_unlock();

			cpuset_hotplug_update_tasks(cs);

			rcu_read_lock();
			css_put(&cs->css);
		}
		rcu_read_unlock();
	}

	/* rebuild sched domains if cpus_allowed has changed */
	if (cpus_updated)
		rebuild_sched_domains();
}



static void kimage_free(struct kimage *image)
{
	kimage_entry_t *ptr, entry;
	kimage_entry_t ind = 0;

	if (!image)
		return;

	kimage_free_extra_pages(image);
	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_INDIRECTION) {
			/* Free the previous indirection page */
			if (ind & IND_INDIRECTION)
				kimage_free_entry(ind);
			/* Save this indirection page until we are
			 * done with it.
			 */
			ind = entry;
		} else if (entry & IND_SOURCE)
			kimage_free_entry(entry);
	}
	/* Free the final indirection page */
	if (ind & IND_INDIRECTION)
		kimage_free_entry(ind);

	/* Handle any machine specific cleanup */
	machine_kexec_cleanup(image);

	/* Free the kexec control pages... */
	kimage_free_page_list(&image->control_pages);

	/*
	 * Free up any temporary buffers allocated. This might hit if
	 * error occurred much later after buffer allocation.
	 */
	if (image->file_mode)
		kimage_file_post_load_cleanup(image);

	kfree(image);
}



MODINFO_ATTR(version);
MODINFO_ATTR(srcversion);

static bool check_symbol(const struct symsearch *syms,
				 struct module *owner,
				 unsigned int symnum, void *data)
{
	struct find_symbol_arg *fsa = data;

	if (!fsa->gplok) {
		if (syms->licence == GPL_ONLY)
			return false;
		if (syms->licence == WILL_BE_GPL_ONLY && fsa->warn) {
			pr_warn("Symbol %s is being used by a non-GPL module, "
				"which will not be allowed in the future\n",
				fsa->name);
		}
	}

#ifdef CONFIG_UNUSED_SYMBOLS
	if (syms->unused && fsa->warn) {
		pr_warn("Symbol %s is marked as UNUSED, however this module is "
			"using it.\n", fsa->name);
		pr_warn("This symbol will go away in the future.\n");
		pr_warn("Please evalute if this is the right api to use and if "
			"it really is, submit a report the linux kernel "
			"mailinglist together with submitting your code for "
			"inclusion.\n");
	}
#endif

	fsa->owner = owner;
	fsa->crc = symversion(syms->crcs, symnum);
	fsa->sym = &syms->start[symnum];
	return true;
}

static int trace_test_buffer_cpu(struct trace_buffer *buf, int cpu)
{
	struct ring_buffer_event *event;
	struct trace_entry *entry;
	unsigned int loops = 0;

	while ((event = ring_buffer_consume(buf->buffer, cpu, NULL, NULL))) {
		entry = ring_buffer_event_data(event);

		/*
		 * The ring buffer is a size of trace_buf_size, if
		 * we loop more than the size, there's something wrong
		 * with the ring buffer.
		 */
		if (loops++ > trace_buf_size) {
			printk(KERN_CONT ".. bad ring buffer ");
			goto failed;
		}
		if (!trace_valid_entry(entry)) {
			printk(KERN_CONT ".. invalid entry %d ",
				entry->type);
			goto failed;
		}
	}
	return 0;

 failed:
	/* disable tracing */
	tracing_disabled = 1;
	printk(KERN_CONT ".. corrupted trace buffer .. ");
	return -1;
}

/*
 * Test the trace buffer to see if all the elements
 * are still sane.
 */
static int trace_test_buffer(struct trace_buffer *buf, unsigned long *count)
{
	unsigned long flags, cnt = 0;
	int cpu, ret = 0;

	/* Don't allow flipping of max traces now */
	local_irq_save(flags);
	arch_spin_lock(&buf->tr->max_lock);

	cnt = ring_buffer_entries(buf->buffer);

	/*
	 * The trace_test_buffer_cpu runs a while loop to consume all data.
	 * If the calling tracer is broken, and is constantly filling
	 * the buffer, this will run forever, and hard lock the box.
	 * We disable the ring buffer while we do this test to prevent
	 * a hard lock up.
	 */
	tracing_off();
	for_each_possible_cpu(cpu) {
		ret = trace_test_buffer_cpu(buf, cpu);
		if (ret)
			break;
	}
	tracing_on();
	arch_spin_unlock(&buf->tr->max_lock);
	local_irq_restore(flags);

	if (count)
		*count = cnt;

	return ret;
}


static struct worker_pool *get_work_pool(struct work_struct *work)
{
	unsigned long data = atomic_long_read(&work->data);
	int pool_id;

	assert_rcu_or_pool_mutex();

	if (data & WORK_STRUCT_PWQ)
		return ((struct pool_workqueue *)
			(data & WORK_STRUCT_WQ_DATA_MASK))->pool;

	pool_id = data >> WORK_OFFQ_POOL_SHIFT;
	if (pool_id == WORK_OFFQ_POOL_NONE)
		return NULL;

	return idr_find(&worker_pool_idr, pool_id);
}

static struct pool_workqueue *unbound_pwq_by_node(struct workqueue_struct *wq,
						  int node)
{
	assert_rcu_or_wq_mutex(wq);
	return rcu_dereference_raw(wq->numa_pwq_tbl[node]);
}

static void wq_unbind_fn(struct work_struct *work)
{
	int cpu = smp_processor_id();
	struct worker_pool *pool;
	struct worker *worker;

	for_each_cpu_worker_pool(pool, cpu) {
		mutex_lock(&pool->attach_mutex);
		spin_lock_irq(&pool->lock);

		/*
		 * We've blocked all attach/detach operations. Make all workers
		 * unbound and set DISASSOCIATED.  Before this, all workers
		 * except for the ones which are still executing works from
		 * before the last CPU down must be on the cpu.  After
		 * this, they may become diasporas.
		 */
		for_each_pool_worker(worker, pool)
			worker->flags |= WORKER_UNBOUND;

		pool->flags |= POOL_DISASSOCIATED;

		spin_unlock_irq(&pool->lock);
		mutex_unlock(&pool->attach_mutex);

		/*
		 * Call schedule() so that we cross rq->lock and thus can
		 * guarantee sched callbacks see the %WORKER_UNBOUND flag.
		 * This is necessary as scheduler callbacks may be invoked
		 * from other cpus.
		 */
		schedule();

		/*
		 * Sched callbacks are disabled now.  Zap nr_running.
		 * After this, nr_running stays zero and need_more_worker()
		 * and keep_working() are always true as long as the
		 * worklist is not empty.  This pool now behaves as an
		 * unbound (in terms of concurrency management) pool which
		 * are served by workers tied to the pool.
		 */
		atomic_set(&pool->nr_running, 0);

		/*
		 * With concurrency management just turned off, a busy
		 * worker blocking could lead to lengthy stalls.  Kick off
		 * unbound chain execution of currently pending work items.
		 */
		spin_lock_irq(&pool->lock);
		wake_up_worker(pool);
		spin_unlock_irq(&pool->lock);
	}
}

static int workqueue_cpu_up_callback(struct notifier_block *nfb,
					       unsigned long action,
					       void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int pi;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		for_each_cpu_worker_pool(pool, cpu) {
			if (pool->nr_workers)
				continue;
			if (!create_worker(pool))
				return NOTIFY_BAD;
		}
		break;

	case CPU_DOWN_FAILED:
	case CPU_ONLINE:
		mutex_lock(&wq_pool_mutex);

		for_each_pool(pool, pi) {
			mutex_lock(&pool->attach_mutex);

			if (pool->cpu == cpu)
				rebind_workers(pool);
			else if (pool->cpu < 0)
				restore_unbound_workers_cpumask(pool, cpu);

			mutex_unlock(&pool->attach_mutex);
		}

		/* update NUMA affinity of unbound workqueues */
		list_for_each_entry(wq, &workqueues, list)
			wq_update_unbound_numa(wq, cpu, true);

		mutex_unlock(&wq_pool_mutex);
		break;
	}
	return NOTIFY_OK;
}

static void wq_unbind_fn(struct work_struct *work)
{
	int cpu = smp_processor_id();
	struct worker_pool *pool;
	struct worker *worker;

	for_each_cpu_worker_pool(pool, cpu) {
		mutex_lock(&pool->attach_mutex);
		spin_lock_irq(&pool->lock);

		/*
		 * We've blocked all attach/detach operations. Make all workers
		 * unbound and set DISASSOCIATED.  Before this, all workers
		 * except for the ones which are still executing works from
		 * before the last CPU down must be on the cpu.  After
		 * this, they may become diasporas.
		 */
		for_each_pool_worker(worker, pool)
			worker->flags |= WORKER_UNBOUND;

		pool->flags |= POOL_DISASSOCIATED;

		spin_unlock_irq(&pool->lock);
		mutex_unlock(&pool->attach_mutex);

		/*
		 * Call schedule() so that we cross rq->lock and thus can
		 * guarantee sched callbacks see the %WORKER_UNBOUND flag.
		 * This is necessary as scheduler callbacks may be invoked
		 * from other cpus.
		 */
		schedule();

		/*
		 * Sched callbacks are disabled now.  Zap nr_running.
		 * After this, nr_running stays zero and need_more_worker()
		 * and keep_working() are always true as long as the
		 * worklist is not empty.  This pool now behaves as an
		 * unbound (in terms of concurrency management) pool which
		 * are served by workers tied to the pool.
		 */
		atomic_set(&pool->nr_running, 0);

		/*
		 * With concurrency management just turned off, a busy
		 * worker blocking could lead to lengthy stalls.  Kick off
		 * unbound chain execution of currently pending work items.
		 */
		spin_lock_irq(&pool->lock);
		wake_up_worker(pool);
		spin_unlock_irq(&pool->lock);
	}
}

static int workqueue_cpu_up_callback(struct notifier_block *nfb,
					       unsigned long action,
					       void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int pi;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		for_each_cpu_worker_pool(pool, cpu) {
			if (pool->nr_workers)
				continue;
			if (!create_worker(pool))
				return NOTIFY_BAD;
		}
		break;

	case CPU_DOWN_FAILED:
	case CPU_ONLINE:
		mutex_lock(&wq_pool_mutex);

		for_each_pool(pool, pi) {
			mutex_lock(&pool->attach_mutex);

			if (pool->cpu == cpu)
				rebind_workers(pool);
			else if (pool->cpu < 0)
				restore_unbound_workers_cpumask(pool, cpu);

			mutex_unlock(&pool->attach_mutex);
		}

		/* update NUMA affinity of unbound workqueues */
		list_for_each_entry(wq, &workqueues, list)
			wq_update_unbound_numa(wq, cpu, true);

		mutex_unlock(&wq_pool_mutex);
		break;
	}
	return NOTIFY_OK;
}

static int workqueue_cpu_up_callback(struct notifier_block *nfb,
					       unsigned long action,
					       void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int pi;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		for_each_cpu_worker_pool(pool, cpu) {
			if (pool->nr_workers)
				continue;
			if (!create_worker(pool))
				return NOTIFY_BAD;
		}
		break;

	case CPU_DOWN_FAILED:
	case CPU_ONLINE:
		mutex_lock(&wq_pool_mutex);

		for_each_pool(pool, pi) {
			mutex_lock(&pool->attach_mutex);

			if (pool->cpu == cpu)
				rebind_workers(pool);
			else if (pool->cpu < 0)
				restore_unbound_workers_cpumask(pool, cpu);

			mutex_unlock(&pool->attach_mutex);
		}

		/* update NUMA affinity of unbound workqueues */
		list_for_each_entry(wq, &workqueues, list)
			wq_update_unbound_numa(wq, cpu, true);

		mutex_unlock(&wq_pool_mutex);
		break;
	}
	return NOTIFY_OK;
}

static void wq_unbind_fn(struct work_struct *work)
{
	int cpu = smp_processor_id();
	struct worker_pool *pool;
	struct worker *worker;

	for_each_cpu_worker_pool(pool, cpu) {
		mutex_lock(&pool->attach_mutex);
		spin_lock_irq(&pool->lock);

		/*
		 * We've blocked all attach/detach operations. Make all workers
		 * unbound and set DISASSOCIATED.  Before this, all workers
		 * except for the ones which are still executing works from
		 * before the last CPU down must be on the cpu.  After
		 * this, they may become diasporas.
		 */
		for_each_pool_worker(worker, pool)
			worker->flags |= WORKER_UNBOUND;

		pool->flags |= POOL_DISASSOCIATED;

		spin_unlock_irq(&pool->lock);
		mutex_unlock(&pool->attach_mutex);

		/*
		 * Call schedule() so that we cross rq->lock and thus can
		 * guarantee sched callbacks see the %WORKER_UNBOUND flag.
		 * This is necessary as scheduler callbacks may be invoked
		 * from other cpus.
		 */
		schedule();

		/*
		 * Sched callbacks are disabled now.  Zap nr_running.
		 * After this, nr_running stays zero and need_more_worker()
		 * and keep_working() are always true as long as the
		 * worklist is not empty.  This pool now behaves as an
		 * unbound (in terms of concurrency management) pool which
		 * are served by workers tied to the pool.
		 */
		atomic_set(&pool->nr_running, 0);

		/*
		 * With concurrency management just turned off, a busy
		 * worker blocking could lead to lengthy stalls.  Kick off
		 * unbound chain execution of currently pending work items.
		 */
		spin_lock_irq(&pool->lock);
		wake_up_worker(pool);
		spin_unlock_irq(&pool->lock);
	}
}

static void rebind_workers(struct worker_pool *pool)
{
	struct worker *worker;

	lockdep_assert_held(&pool->attach_mutex);

	/*
	 * Restore CPU affinity of all workers.  As all idle workers should
	 * be on the run-queue of the associated CPU before any local
	 * wake-ups for concurrency management happen, restore CPU affinty
	 * of all workers first and then clear UNBOUND.  As we're called
	 * from CPU_ONLINE, the following shouldn't fail.
	 */
	for_each_pool_worker(worker, pool)
		WARN_ON_ONCE(set_cpus_allowed_ptr(worker->task,
						  pool->attrs->cpumask) < 0);

	spin_lock_irq(&pool->lock);
	pool->flags &= ~POOL_DISASSOCIATED;

	for_each_pool_worker(worker, pool) {
		unsigned int worker_flags = worker->flags;

		/*
		 * A bound idle worker should actually be on the runqueue
		 * of the associated CPU for local wake-ups targeting it to
		 * work.  Kick all idle workers so that they migrate to the
		 * associated CPU.  Doing this in the same loop as
		 * replacing UNBOUND with REBOUND is safe as no worker will
		 * be bound before @pool->lock is released.
		 */
		if (worker_flags & WORKER_IDLE)
			wake_up_process(worker->task);

		/*
		 * We want to clear UNBOUND but can't directly call
		 * worker_clr_flags() or adjust nr_running.  Atomically
		 * replace UNBOUND with another NOT_RUNNING flag REBOUND.
		 * @worker will clear REBOUND using worker_clr_flags() when
		 * it initiates the next execution cycle thus restoring
		 * concurrency management.  Note that when or whether
		 * @worker clears REBOUND doesn't affect correctness.
		 *
		 * ACCESS_ONCE() is necessary because @worker->flags may be
		 * tested without holding any lock in
		 * wq_worker_waking_up().  Without it, NOT_RUNNING test may
		 * fail incorrectly leading to premature concurrency
		 * management operations.
		 */
		WARN_ON_ONCE(!(worker_flags & WORKER_UNBOUND));
		worker_flags |= WORKER_REBOUND;
		worker_flags &= ~WORKER_UNBOUND;
		ACCESS_ONCE(worker->flags) = worker_flags;
	}

	spin_unlock_irq(&pool->lock);
}

void freeze_workqueues_begin(void)
{
	struct workqueue_struct *wq;
	struct pool_workqueue *pwq;

	mutex_lock(&wq_pool_mutex);

	WARN_ON_ONCE(workqueue_freezing);
	workqueue_freezing = true;

	list_for_each_entry(wq, &workqueues, list) {
		mutex_lock(&wq->mutex);
		for_each_pwq(pwq, wq)
			pwq_adjust_max_active(pwq);
		mutex_unlock(&wq->mutex);
	}

	mutex_unlock(&wq_pool_mutex);
}

bool freeze_workqueues_busy(void)
{
	bool busy = false;
	struct workqueue_struct *wq;
	struct pool_workqueue *pwq;

	mutex_lock(&wq_pool_mutex);

	WARN_ON_ONCE(!workqueue_freezing);

	list_for_each_entry(wq, &workqueues, list) {
		if (!(wq->flags & WQ_FREEZABLE))
			continue;
		/*
		 * nr_active is monotonically decreasing.  It's safe
		 * to peek without lock.
		 */
		rcu_read_lock_sched();
		for_each_pwq(pwq, wq) {
			WARN_ON_ONCE(pwq->nr_active < 0);
			if (pwq->nr_active) {
				busy = true;
				rcu_read_unlock_sched();
				goto out_unlock;
			}
		}
		rcu_read_unlock_sched();
	}
out_unlock:
	mutex_unlock(&wq_pool_mutex);
	return busy;
}

void thaw_workqueues(void)
{
	struct workqueue_struct *wq;
	struct pool_workqueue *pwq;

	mutex_lock(&wq_pool_mutex);

	if (!workqueue_freezing)
		goto out_unlock;

	workqueue_freezing = false;

	/* restore max_active and repopulate worklist */
	list_for_each_entry(wq, &workqueues, list) {
		mutex_lock(&wq->mutex);
		for_each_pwq(pwq, wq)
			pwq_adjust_max_active(pwq);
		mutex_unlock(&wq->mutex);
	}

out_unlock:
	mutex_unlock(&wq_pool_mutex);
}

int main() {
	for_each_possible_cpu(cpu) {
		struct worker_pool *pool;

		i = 0;
		for_each_cpu_worker_pool(pool, cpu) {
			BUG_ON(init_worker_pool(pool));
			pool->cpu = cpu;
			cpumask_copy(pool->attrs->cpumask, cpumask_of(cpu));
			pool->attrs->nice = std_nice[i++];
			pool->node = cpu_to_node(cpu);

			/* alloc pool ID */
			mutex_lock(&wq_pool_mutex);
			BUG_ON(worker_pool_assign_id(pool));
			mutex_unlock(&wq_pool_mutex);
		}
	}

	for_each_subsys(ss, ssid) {
		if (enable & (1 << ssid)) {
			if (cgrp->subtree_control & (1 << ssid)) {
				enable &= ~(1 << ssid);
				continue;
			}

			/* unavailable or not enabled on the parent? */
			if (!(cgrp_dfl_root.subsys_mask & (1 << ssid)) ||
			    (cgroup_parent(cgrp) &&
			     !(cgroup_parent(cgrp)->subtree_control & (1 << ssid)))) {
				ret = -ENOENT;
				goto out_unlock;
			}
		} else if (disable & (1 << ssid)) {
			if (!(cgrp->subtree_control & (1 << ssid))) {
				disable &= ~(1 << ssid);
				continue;
			}

			/* a child has it enabled? */
			cgroup_for_each_live_child(child, cgrp) {
				if (child->subtree_control & (1 << ssid)) {
					ret = -EBUSY;
					goto out_unlock;
				}
			}
		}
	}

			cgroup_for_each_live_child(child, cgrp) {
			DEFINE_WAIT(wait);

			if (!cgroup_css(child, ss))
				continue;

			cgroup_get(child);
			prepare_to_wait(&child->offline_waitq, &wait,
					TASK_UNINTERRUPTIBLE);
			cgroup_kn_unlock(of->kn);
			schedule();
			finish_wait(&child->offline_waitq, &wait);
			cgroup_put(child);

			return restart_syscall();
		}

			for_each_subsys(ss, ssid) {
		if (!(css_enable & (1 << ssid)))
			continue;

		cgroup_for_each_live_child(child, cgrp) {
			DEFINE_WAIT(wait);

			if (!cgroup_css(child, ss))
				continue;

			cgroup_get(child);
			prepare_to_wait(&child->offline_waitq, &wait,
					TASK_UNINTERRUPTIBLE);
			cgroup_kn_unlock(of->kn);
			schedule();
			finish_wait(&child->offline_waitq, &wait);
			cgroup_put(child);

			return restart_syscall();
		}
	}

		for_each_subsys(ss, ssid) {
		if (!(enable & (1 << ssid)))
			continue;

		cgroup_for_each_live_child(child, cgrp) {
			if (css_enable & (1 << ssid))
				ret = create_css(child, ss,
					cgrp->subtree_control & (1 << ssid));
			else
				ret = cgroup_populate_dir(child, 1 << ssid);
			if (ret)
				goto err_undo_css;
		}
	}

		for_each_subsys(ss, ssid) {
		if (!(disable & (1 << ssid)))
			continue;

		cgroup_for_each_live_child(child, cgrp) {
			struct cgroup_subsys_state *css = cgroup_css(child, ss);

			if (css_disable & (1 << ssid)) {
				kill_css(css);
			} else {
				cgroup_clear_dir(child, 1 << ssid);
				if (ss->css_reset)
					ss->css_reset(css);
			}
		}
	}

		for_each_subsys(ss, ssid) {
		if (!(enable & (1 << ssid)))
			continue;

		cgroup_for_each_live_child(child, cgrp) {
			struct cgroup_subsys_state *css = cgroup_css(child, ss);

			if (!css)
				continue;

			if (css_enable & (1 << ssid))
				kill_css(css);
			else
				cgroup_clear_dir(child, 1 << ssid);
		}
	}

	for_each_root(root) {
		bool name_match = false;

		if (root == &cgrp_dfl_root)
			continue;

		/*
		 * If we asked for a name then it must match.  Also, if
		 * name matches but sybsys_mask doesn't, we should fail.
		 * Remember whether name matched.
		 */
		if (opts.name) {
			if (strcmp(opts.name, root->name))
				continue;
			name_match = true;
		}

		/*
		 * If we asked for subsystems (or explicitly for no
		 * subsystems) then they must match.
		 */
		if ((opts.subsys_mask || opts.none) &&
		    (opts.subsys_mask != root->subsys_mask)) {
			if (!name_match)
				continue;
			ret = -EBUSY;
			goto out_unlock;
		}

		if (root->flags ^ opts.flags)
			pr_warn("new mount options do not match the existing superblock, will be ignored\n");

		/*
		 * We want to reuse @root whose lifetime is governed by its
		 * ->cgrp.  Let's check whether @root is alive and keep it
		 * that way.  As cgroup_kill_sb() can happen anytime, we
		 * want to block it by pinning the sb so that @root doesn't
		 * get killed before mount is complete.
		 *
		 * With the sb pinned, tryget_live can reliably indicate
		 * whether @root can be reused.  If it's being killed,
		 * drain it.  We can use wait_queue for the wait but this
		 * path is super cold.  Let's just sleep a bit and retry.
		 */
		pinned_sb = kernfs_pin_sb(root->kf_root, NULL);
		if (IS_ERR(pinned_sb) ||
		    !percpu_ref_tryget_live(&root->cgrp.self.refcnt)) {
			mutex_unlock(&cgroup_mutex);
			if (!IS_ERR_OR_NULL(pinned_sb))
				deactivate_super(pinned_sb);
			msleep(10);
			ret = restart_syscall();
			goto out_free;
		}

		ret = 0;
		goto out_unlock;
	}


		for_each_root(root) {
		struct cgroup *from_cgrp;

		if (root == &cgrp_dfl_root)
			continue;

		down_read(&css_set_rwsem);
		from_cgrp = task_cgroup_from_root(from, root);
		up_read(&css_set_rwsem);

		retval = cgroup_attach_task(from_cgrp, tsk, false);
		if (retval)
			break;
	}

	for_each_root(root) {
		struct cgroup_subsys *ss;
		struct cgroup *cgrp;
		int ssid, count = 0;

		if (root == &cgrp_dfl_root && !cgrp_dfl_root_visible)
			continue;

		seq_printf(m, "%d:", root->hierarchy_id);
		for_each_subsys(ss, ssid)
			if (root->subsys_mask & (1 << ssid))
				seq_printf(m, "%s%s", count++ ? "," : "", ss->name);
		if (strlen(root->name))
			seq_printf(m, "%sname=%s", count ? "," : "",
				   root->name);
		seq_putc(m, ':');
		cgrp = task_cgroup_from_root(tsk, root);
		path = cgroup_path(cgrp, buf, PATH_MAX);
		if (!path) {
			retval = -ENAMETOOLONG;
			goto out_unlock;
		}
		seq_puts(m, path);
		seq_putc(m, '\n');
	}


		unsigned long data = atomic_long_read(&work->data);
	int pool_id;

	assert_rcu_or_pool_mutex();

	if (data & WORK_STRUCT_PWQ)
		return ((struct pool_workqueue *)
			(data & WORK_STRUCT_WQ_DATA_MASK))->pool;

	pool_id = data >> WORK_OFFQ_POOL_SHIFT;
	if (pool_id == WORK_OFFQ_POOL_NONE)
		return NULL;

	return idr_find(&worker_pool_idr, pool_id);
}