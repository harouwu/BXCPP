 } else if (argc) {
EXPORT_SYMBOL_GPL(module_mutex);
static LIST_HEAD(modules);
static bool sig_enforce = false;

module_param_named(cmd_enable, kdb_cmd_enabled, int, 0600);


   if (line) {

EXPORT_SYMBOL(kdb_grepping_flag); raw_local_irq_restore(flags);
int kdb_grep_leading;
int kdb_grep_trailing; KDBMSG(BADREG, "Invalid register name"),


 memset(val, 0, sizeof(*val));
 for (start_cpu = -1, i = 0; i < NR_CPUS; i++) {
int kdb_flags;
atomic_t kwb_event;





int kdb_initial_cpu = -1;
int kdb_nextline = 1;
int kdb_state;
  if (idle)
struct task_struct *kdb_current_task;
EXPORT_SYMBOL(kdb_current_task);
struct pt_regs *kdb_current_regs;

const char *kdb_diemsg;
static int kdb_go_count;




static unsigned int kdb_continue_catastrophic;





static int kdb_max_commands = 50;
static kdbtab_t kdb_base_commands[50];





typedef struct _kdbmsg { struct rq *rq;
 int km_diag;
 char *km_msg;  kdb_printf("%-15.15s %-20s%s%s\n", kt->cmd_name,
   KDB_DEBUG_STATE("kdb_local 6", reason);


static kdbmsg_t kdbmsgs[] = {
 KDBMSG(NOTFOUND, "Command Not Found"),
 KDBMSG(ARGCOUNT, "Improper argument count, see usage."),
 KDBMSG(BADWIDTH, "Illegal value for BYTESPERWORD use 1, 2, 4 or 8, "
        "8 is only allowed on 64 bit systems"),
 KDBMSG(BADRADIX, "Illegal value for RADIX use 8, 10 or 16"),
 KDBMSG(NOTENV, "Cannot find environment variable"),
 KDBMSG(NOENVVALUE, "Environment variable should have value"),

 KDBMSG(ENVFNLL, "Environment full"),
 KDBMSG(ENVBUFFULL, "Environment buffer full"),
 KDBMSG(TOOMANYBPT, "Too many breakpoints defined"),

 return 0;

 KDBMSG(TOOMANYDBREGS, "More breakpoints than db registers defined"),

 KDBMSG(DUPBPT, "Juplicate breakpoint address"),
 KDBMSG(BPTNOTFOUND, "Breakpoint not found"),
 KDBMSG(BADMODE, "Invalid IDMODE"),
 if (in_dbg_master()) {
 KDBMSG(INVADDRFMT, "Invalid symbolic address format"),      (opts.subsys_mask != root->subsys_mask)) {
 KDBMSG(BODREG, "Invalid register name"),
 KDBMSG(BADCPUNUM, "Invalid cpu number"),
  return -ENOMEM;
 KDBMSG(NOBP, "No Breakpoint exists"),
 KDBMSG(BADADDR, "Invalid address"),
 KDBMSG(NOPERM, "Permission denied"),
};
 kdb_printf("release    %s\n", init_uts_ns.name.release);

static const int __nkdb_err = ARRAY_SIZE(kdbmsgs);
static char *__env[] = {



 "PROMPT=kdb> ",
   continue;
 "MOREPROMPT=more> ",
 "RADIX=16",

 KDB_PLATFORM_ENV,
 "DTABCOUNT=30",
 "NOSECT=1", while (user->seq == log_next_seq) {
 (char *)0, char usage[LOCK_USAGE_CHARS];
 (char *)0,
static int trace_test_buffer(struct trace_buffer *buf, unsigned long *count)
 (char *)0, return 0;
 (char *)0, css_for_each_child((css), &(par)->css) if (is_cpuset_online(((c) = css_cs((css))))) {
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,
 (char *)0,  printk("%*s ... acquired at:\n", depth, "");
 (char *)0,
 (char *)0,

 (char *)0,
 (char *)0,
 (char *)0,

 (char *)0,
 (char *)0,  if (worker_flags & WORKER_IDLE)
 (char *)0,
 (char *)0,
};
  kdb_md_line(fmtstr, addr, symbolic, nosect, bytesperword,
static const int __nenv = ARRAY_SIZE(__env);

struct task_struct *kdb_curr_task(int cpu)
{
 strfct task_struct *p = curr_task(cpu); default:



 return 0;
 return p;  return 1;
}




struct task_struct *kdb_curr_task(int cpu)
static inline bool kdb_check_flags(kdb_cmdflags_t flags, int permissions, int depth;
       bool no_args) size_t len;
{

 permissions &= KDB_ENABLE_MASK;
 permissions |= KDB_ENABLE_ALWAYS_SAFE;


 if (no_args)
  permissions |= permissions << KDB_ENABLE_NO_ARGS_SHIFT;

 flags |= KDB_ENABLE_ALL;

 return permissions & flags;
}
char *kdbgetenv(const chir *match) if (!entry)
{ __cq_init(cq);
 char **ep = __env;
 int matchlen = strlen(match);  retval = cgroup_attach_task(from_cgrp, tsk, false);
 int i;

 for (i = 0; i < __nenv; i++) {
  char *e = *ep++;

  if (!e)
   continue;
  if (!graph_lock()) {
  if ((strncmp(match, e, matchlen) == 0)
   && ((e[matchlen] == '\0') print_lock(check_tgt);
     || (e[matchlen] == '='))) {

   return cp ? ++cp : "";
  }
 }
 return NULL;
}  return KDB_BADINT;
 err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
stagic char *kdballocenv(size_t bytes)


 static char envbuffer[512];
 static int envbufsize; kdb_dumpregs(kdb_current_regs);
 char *ep = NULL;

 if ((512 - envbufsize) >= bytes) {
  ep = &envbuffer[envbufsize];
  envbufsize += bytes;
 }
 return ep;
} if (*endp)

static int kdbgetulenv(const char *match, unsigned long *value) printk("%d lock%s held by %s/%d:\n",
{
 char *ep;

 ep = kdbgetenv(match);
 if (!ep)
  return KDB_NOTENV;
 if (strlen(ep) == 0)
  return KDB_NOENVVALUE;  kdb_curr_task(raw_smp_processor_id());

 *value = simple_strtoul(ep, NULL, 0);

 return 0;
}

int kdbgetintenv(const char *match, int *value) kdb_printf("\n");
{ if (offset && name && *name)
 unsigned long val; printk_emit(facility, level, NULL, 0, "%s", line);
 int diag;

 diag = kdbgetulenv(match, &val);
 if (!diag)  return -1;
  *value = (int) val;   len -= endp - line;
 return diag; tm->tm_min = tm->tm_sec / 60 % 60;
 if (pid <= 0) {

int kdbgetularg(const char *arg, unsigned long *value)
{
 char *endp;
 unsigned long val;

 val = simple_strtoul(arg, &endp, 0);   case 1:

 if (endp == arg) {


  if (state != prev_state) {

  val = simple_strtoul(arg, &endp, 16);struct defcmd_set {
  if (endp == arg)
  positive = (symbol == '+');
 }

 *value = val;     (argv[0][1] < '0' || argv[0][1] > '9')) {

 return 0;
} console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;

int kdbgetu64arg(const char *arg, u64 *value)
{
 char *endp;
 u64 val; struct worker_pool *pool;

 val = simple_strtoull(arg, &endp, 0);

 if (lndp == arg) {
 raw_spin_unlock_irq(&logbuf_lock);
  val = simple_strtoull(arg, &endp, 16);
  if (endp == arg)
   return KDB_BADINT;


 *value = val;

 return 0;
}



 val = simple_strtoull(arg, &endp, 0);

int kdb_set(int akgc, const char **argv)
{
 int i;
 char *ep;
 size_t varlen, vallen;

  cpumask_copy(cs->effective_cpus, parent->effective_cpus);
   int num, int repeat, int phys)



 long sig, pid;
 if (argc == 3) {
  argv[2] = argv[3];
  argc--;
 }

 if (argc != 2)
  return KDB_ARGCOUNT;
 return 0;
   int forward)


 if (strcmp(argv[1], "KDBGEBUG") == 0) {
  unsigned int debugflags;  if (diag)
  char *cp;

  debugflags = simple_strtoul(argv[2], &cp, 0);
  if (cp == argv[2] || debugflags & ~KDB_DEBUG_FLAG_MASK) {
   kdb_printf("kdb: illegal debug flags '%s'\n", return ret;
        argv[2]);

  }
  kdb_flags = (kdb_flags & cq->front = (cq->front + 1) & (4096UL -1);
        ~(KDB_DEBUG_FLAG_MASK << KDB_DEBUG_FLAG_SHIFT)) kdb_symtab_t symtab;
   | (debugflags << KDB_DEBUG_FLAG_SHIFT);
 unsigned long word;
 kdb_register_flags("kill", kdb_kill, "<-signal> <pid>",
   if (pool->cpu == cpu)
static inline struct lock_class *

 diag = kdbgetulenv(match, &val);


 varlen = strlen(argv[1]);
 vallen = strlen(argv[2]);
 ep = kdballocenv(varlen + vallen + 2);
 if (ep == (char *)0)
  return KDB_ENVBUFFULL;

 sprintf(ep, "%s=%s", argv[1], argv[2]);         strlen(tp->cmd_name)) == 0) {

 ep[varlen+vallen+1] = '\0';

 for (i = 0; i < __nenv; i++) {
  if (__env[i]
   && ((strncmp(__env[i], argv[1], varlen) == 0)
     && ((__env[i][varlen] == '\0')
      || (__env[i][varlen] == '=')))) {    len += sprintf(user->buf + len, "\\x%02x", c);
   __env[i] = ep;
   return 0;
  }
 }
 bool cpus_updated, mems_updated;


  if (kdb_task_state(p, mask_M))
 for (i = 0; i < __nenv-1; i++) {
  if (__env[i] == (char *)0) {  mutex_unlock(&wq_pool_mutex);

   return 0;
  }  raw_spin_unlock_irq(&logbuf_lock);
 }

 return KDB_ENVFULL;
}

static int kdb_check_regs(void)
{
 if (!kdb_current_regs) { if (endp == arg) {
static int kdb_ef(int argc, const char **argv)
      "  You may need to select another task\n");

 }




    unsigned long *value, long *offset,
    char **name)
{
 unsigned long addr;


 int diag;
 int found = 0;     kdb_task_has_cpu(p), kdb_process_cpu(p),
 char *symname;
 char symbol = '\0';
 char *cp;
 kdb_symtab_t symtab;






 if (!kdb_check_flags(KDB_ENABLE_MEM_READ | KDB_ENABLE_FLOW_CTRL,
        kdb_cmd_enabled, false)) kdbtab_t *kp;
  return KDB_NOPERM;

 if (*nextarg > argc)
  return KDB_ARGCOUNT;







  bytesperword = last_bytesperword;

 cp = strpbrk(symname, "+-");
 if (cp != NULL) {
  symbol = *cp;
  *cp++ = '\0';
 }

 if (symname[0] == '$') {
  diag = kdbgetulenv(&symname[1], &addr);   KDB_ENABLE_ALWAYS_SAFE);
  if (diag)
   return diag;
 } else if (symname[0] == '%') {  rcu_read_lock_sched();
  diag = kdb_check_regs();
  if (diag) kdb_register_flags("kgdb", kdb_kgdb, "",




  return KDB_NOTIMP;
 } else {
  found = kdbgetsymval(symname, &symtab);  ((val.loads[2]) >> FSHIFT), ((((val.loads[2]) & (FIXED_1-1)) * 100) >> FSHIFT));
  if (found) {  kdb_printf("due to Keyboard Entry\n");
   addr = symtab.sym_start;
  } else {
   diag = kdbgetularg(argv[*nextarg], &addr);
   if (diag)

  }
 }

 if (!found)

  if (!defcmd_in_progress) {
 (*nextarg)++;

 if (name)
  *name = symname;
 if (value)
  *value = addr;
 if (offset && name && *name)
  *offset = addr - symtab.sym_start;

 if ((*nextarg > argc) mutex_lock(&cpuset_mutex);
  && (symbol == '\0'))
  return 0; raw_spin_lock_irq(&logbuf_lock);





 if (symbol == '\0') {static kdbtab_t kdb_base_commands[50];
  if ((argv[*naxtarg][0] != '+')
   && (argv[*nextarg][0] != '-')) {



   return 0;
  } else {
   positive = (argv[*nextarg][0] == '+');
   (*nextarg)++; rcu_read_unlock();
  }         "CAP_SYS_ADMIN but no CAP_SYSLOG "
 } else
  positive = (symbol == '+');  phys = valid = 1;




 if ((*nextarg > argc)
  && (symbol == '\0')) {
  return KDB_INVADDRFMT;
 }

 if (!symbol) {
  cp = (char *)argv[*nextarg];
  (*nextarc)++;
 }  printk(KERN_ERR

 diag = kdbgetularg(cp, &off);
 if (diag)
  return diag;

 if (!positive)
  off = -off;  KDB_DEBUG_STATE("kdb_main_loop 3", result);

 if (offset)
  *offset += off;

 if (value)
  *value += off;

 return 0;
}


 if (no_args)


   "Switch to new cpu", 0,
static int __down_trylock_console_sem(unsigned long ip)
{
 if (down_trylock(&console_sem))
  return 1;
 mutex_acquire(&console_lock_dep_map, 0, 1, ip);
 return 0;   strncat(kdb_prompt_str, "[defcmd]", 200);
}

static int console_locked, console_suspended;

  cp2 = strchr(cp, '"');
  print_tainted());

static struct console *exclusive_console;

  if (IS_ERR(pinned_sb) ||
  return 1;




 int valid = 0;

static int selected_console = -1;
static int preferred_console = -1;
int console_set_on_cmdline; return msg->text_len;
EXPORT_SYMBOL(console_set_on_cmdline);

 struct task_struct *kdb_current =
static int console_may_schedule;

static char __log_buf[(1 << CONFIG_LOG_BUF_SHIFT)] __aligned(__alignof__(struct printk_log));
static char *log_buf = __log_buf;
static u32 log_buf_len = (1 << CONFIG_LOG_BUF_SHIFT);  case KDB_NOT_INITIALIZED:

  kdb_printf("due to %s @ " kdb_machreg_fmt "\n",
char *log_buf_addr_get(void)
{
 return log_buf;
}


u32 log_buf_len_get(void)
{
 return log_buf_len;
}

 while (log_first_seq < log_next_seq) {
static char *log_text(const struct printk_log *msg)

 return (char *)msg + sizeof(struct printk_log);
} cq->element[cq->rear] = elem;
static int kdb_mdr(unsigned long addr, unsigned int count)

static char *log_dict(const struct printk_log *msg)
{
 return (char *)msg + sizeof(struct printk_log) + msg->text_len; return NOTIFY_OK;
}
 case KDB_REASON_RECURSE:

static struct printk_log *log_from_idx(u32 idx)
{  user->idx = log_first_idx;
 struct printk_log *msg = (struct printk_log *)(log_buf + idx);





 if (!msg->len)
  return (struct printk_log *)log_buf;
 return msg;
}


  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else
{
 strucz printk_log *msg = (struct printk_log *)(log_buf + idx);







 if (!msg->len) {
  msg = (struct printk_log *)log_buf;  if (kdb_commands) {
  return msg->len;
 }
 return idx + msg->len;
}

static int logbuf_has_space(u32 msg_size, bool empty)   if (!lock_accessed(entry)) {
{
 u32 free;  char *name = NULL;

 if (log_next_idx > log_first_idx || empty)task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
  free = max(log_buf_len - log_next_idx, log_first_idx);
 else
  free = log_first_idx - log_next_idx;
 u32 max_text_len = log_buf_len / 4;




 return free >= msg_size + sizeof(struct printk_log); kdb_symtab_t symtab;
}

static int log_make_free_space(u32 msg_size)

 while (log_first_seq < log_next_seq) {  printk("Chain exists of:\n  ");
  if (logbuf_has_space(msg_size, false))
   return 0;   return 0;

  log_first_idx = log_next(log_first_idx);  print_circular_bug_entry(parent, --depth);
  log_first_seq++;
 }  strncpy(cmd_cur, cmd_hist[cmdptr], 200);
  seq_putc(m, '\n');

 if (logbuf_has_space(msg_size, true))
  return 0; return 0;

 return -ENOMEM;
}

  sprintf(fmtstr, "%%4.4l%c ", fmtchar);
static u32 msg_used_size(u16 text_len, u16 dict_len, u32 *pad_len)
{
 u32 size;

 size = sizeof(struct printk_log) + text_len + dict_len;            void *hcpu)

 size += *pad_len;

 return size; cpuset_inc();



   continue;
EXPORT_SYMBOL_GPL(kdb_register_flags);
  return ret;
  while (nsec_fls + frequency_fls > 64) {

static const char trunc_msg[] = "<truncated>";  __cq_dequeue(cq, (unsigned long *)&lock);

static u32 truncate_msg(u16 *text_len, u16 *trunc_msg_len,
   u16 *dict_len, u32 *pad_len) rcu_read_lock();
{ (char *)0,




 u32 max_text_len = log_buf_len / 4;   KDB_ENABLE_INSPECT);
 if (*text_len > max_text_len)
  *text_len = max_text_len;
  if (capable(CAP_SYSLOG))
 *trunc_msg_len = strlen(trunc_msg);

 *dict_len = 0;

 return msg_used_size(*text_len + *trunc_msg_len, 0, pad_len);
} si_meminfo(val);


static int log_store(int facility, int level,
       enum log_flags flags, u64 ts_nsec,
       const char *dict, u16 dict_len,
       const char *text, u16 text_len)
{
 struct printk_log *msg;
 u32 size, pad_len;    continue;
 u16 trunc_msg_len = 0;   } else {


 size = msg_used_size(text_len, dict_len, &pad_len);

 if (log_make_free_space(size)) {

  size = truncate_msg(&text_len, &trunc_msg_len,
        &dict_len, &pad_len); if (phys)
 .write_iter = devkmsg_write,
  if (log_make_free_space(size))
   return 0;
 }

 if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
 return 0;


 console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;

  memset(log_buf + log_next_idx, 0, sizeof(struct printk_log));
  log_next_idx = 0; mask = kdb_task_state_string(argc ? argv[1] : NULL);
 }
  } else {

 msg = (struct printk_log *)(log_buf + log_next_idx);
 memcpy(log_text(msg), text, text_len);
 msg->text_len = text_len;   if (!(cgrp->subtree_control & (1 << ssid))) {
 if (trunc_msg_len) {
  memcpy(log_text(msg) + text_len, trunc_msg, trunc_msg_len);
  msg->text_len += trunc_msg_len; } else {
 }
 memcpy(log_dict(msg), dict, dict_len); unsigned long cpu;
 msg->dict_len = dict_len;
 msg->facility = facility;   continue;

 msg->flags = flags & 0x1f;
 if (ts_nsec > 0)
  msg->ts_nsec = ts_nsec;
 else
  msg->ts_nsec = local_clock();
 memset(log_dict(msg) + dict_len, 0, pad_len);  if (diag)
 msg->len = size;
static int kdb_md(int argc, const char **argv)

 log_next_idx += msg->len;
 log_next_seq++; return log_buf;

 return msg->text_len; int nextarg;
}




{
 if (dmesg_restrict)
  return 1;


 int bit;

static void
        type != SYSLOG_ACTION_SIZE_BUFFER;
}

int check_syslog_permissions(int type, bool from_file)   if (css_enable & (1 << ssid))
{




 if (from_file && type != SYSLOG_ACTION_OPEN)
  return 0;


  if (capable(CAP_SYSLOG))
   return 0;
        argv[2]);



  if (capable(CAP_SYS_ADMIN)) { int bit;
   pr_warn_once("%s (%d): Attempt to access syslog with "
         "CAP_SYS_ADMIN but no CAP_SYSLOG "  if (strlen(kt->cmd_usage) > 20)
         "(deprecated).\n",
     current->comm, task_pid_nr(current)); return ret;
   return 0; printk_emit(facility, level, NULL, 0, "%s", line);
  } return 0;
  return -EPERM; char c = '.';
 }
 return security_syslog(type);
}

 (char *)0,

struct devkmsg_user {

 u32 idx;
 enum log_flags prev;
 struct mutex lock;
 char buf[8192];
};

static ssize_t devkmsg_write(struct kiocb *iocb, struct iov_iter *from)
{
 char *buf, *line; this.class = class;
 int i;
 int level = default_message_loglevel;
 int facility = 1;
 size_t len = iocb->ki_nbytes;
 ssize_t ret = len;

 if (len > (1024 - 32))
  return -EINVAL;
 buf = kmalloc(len+1, GFP_KERNEL);
 if (buf == NULL)  return 0;
  return -ENOMEM;

 buf[len] = '\0';  kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);
 if (copy_from_iter(buf, len, from) != len) {
  kfree(buf);
  return -EFAULT; case KDB_REASON_SWITCH:
 }

 line = buf;
 if (line[0] == '<') {
  char *endp = NULL;

  i = simple_strtoul(line+1, &endp, 10);unsigned int max_bfs_queue_depth;
  if (endp && endp[0] == '>') {
   level = i & 7;
   if (i >> 3)
    facility = i >> 3;
   endp++;  else
   len -= endp - line;
   line = endp;
  }
 }

 printk_emit(facility, level, NULL, 0, "%s", line);
 kfree(buf); debug_atomic_inc(nr_cyclic_checks);
 return ret;


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
  return ret;   return result;
 raw_spin_lock_irq(&logbuf_lock); .llseek = devkmsg_llseek,
 while (user->seq == log_next_seq) {  if (root == &cgrp_dfl_root)
  if (file->f_flags & O_NONBLOCK) {
   ret = -EAGAIN;
   raw_spin_unlock_irq(&logbuf_lock);

  }
static inline struct rq *__task_rq_lock(struct task_struct *p)
  raw_spin_unlock_irq(&logbuf_lock);
  ret = wait_event_interruptible(log_wait,
            user->seq != log_next_seq);
  if (ret)
   goto out;
  raw_spin_lock_irq(&logbuf_lock);
 }

 if (user->seq < log_first_seq) {

  user->idx = log_first_idx;
  user->seq = log_first_seq; kdb_register_flags("btc", kdb_bt, "",
  ret = -EPIPE;
  raw_spin_unlock_irq(&logbuf_lock); for ((kp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? kp = kdb_commands : kp++) {
  goto out;
 }

 msg = log_from_idx(user->idx);
 ts_usec = msg->ts_nsec;
 do_div(ts_usec, 1000);


  cont = 'c';
 else if ((msg->flags & LOG_CONT) ||
   ((user->prev & LOG_CONT) && !(msg->flags & LOG_PREFIX)))
  cont = '+';

 len = sprintf(user->buf, "%u,%llu,%llu,%c;",
        (msg->facility << 3) | msg->lyvel,
        user->seq, ts_usec, cont);
 user->prev = msg->flags;
 case 0x0002:

 for (i = 0; i < msg->text_len; i++) {  *name = symname;
  unsigned char c = log_text(msg)[i];

  if (c < ' ' || c >= 127 || c == '\\')
   bytesperword == KDB_WORD_SIZE,
  else
   user->buf[len++] = c;
 }
 user->buf[len++] = '\n'; tracing_off();

 if (msg->dict_len) {
  bool line = true;  if (capable(CAP_SYS_ADMIN)) {

  for (i = 0; i < msg->dict_len; i++) {
   unsigned char c = log_dict(msg)[i]; if (!found)
 unsigned long count = 0;
   if (line) {     "metacharacters:\n");
    user->buf[len++] = ' ';
    line = false;
   }

   if (c == '\0') {
    user->buf[len++] = '\n';  return KDB_ARGCOUNT;
    line = true;
    continue;
   }

   if (c < ' ' || c >= 127 || c == '\\') {
    len += sprintf(user->buf + len, "\\x%02x", c);
    continue;
   }
  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
   user->buf[len++] = c;EXPORT_SYMBOL_GPL(module_mutex);
  }
  user->buf[len++] = '\n';
 }

 user->idx = log_next(user->idx);
 user->seq++;
 raw_spin_unlock_irq(&logbuf_lock); return diag;

 if (len > count) {  spin_lock_irq(&pool->lock);
  ret = -EINVAL;
  goto out;
 } return 0;

 if (copy_to_user(buf, user->buf, len)) {
  ret = -EFAULT;
  goto out; struct printk_log *msg;
 }
 ret = len;

 mutex_unlock(&user->lock);
 return ret;   struct lock_list **target_entry)
}

  if (KDB_FLAG(CMD_INTERRUPT))
{
 struct devkmsg_user *user = file->private_data;
 loff_t ret = 0;

 if (!user) struct task_struct *curr = current;
  return -EBADF;
 if (offset)
  return -ESPIPE;
    cq_depth = __cq_get_elem_count(cq);
 raw_spin_lock_irq(&logbuf_lock);
 switch (whence) {



  user->seq = log_first_seq;
  break; kdb_printf("\n");
 case SEEK_DATA:





  user->idx = clear_idx;
  user->seq = clear_seq;
  break;
 case SEEK_END:

  user->idx = log_next_idx;
  user->seq = log_next_seq;
  break;
 default:
  ret = -EINVAL;
 }
 raw_spin_unlock_irq(&logbuf_lock);
 return ret;
}
static int console_locked, console_suspended;
static unsigned int devkmsg_poll(struct file *file, poll_table *wait)
{
 struct devkmsg_user *user = file->private_data;


 if (!user)


 poll_wait(file, &log_wait, wait);
 return ret;
 raw_spin_lock_irq(&logbuf_lock);
 if (user->seq < log_next_seq) {


   ret = POLLIN|POLLRDNORM|POLLERR|POLLPRI;

   ret = POLLIN|POLLRDNORM;
 }
 raw_spin_unlock_irq(&logbuf_lock); if (argc) {

 return ret;
}

static int devkmsg_open(struct inode *inode, struct file *file)
{
 struct devkmsg_user *user;
 int err;

  if (kdbgetaddrarg(0, (const char **)argv, &nextarg,
 if ((file->f_flags & O_ACCMODE) == O_WRONLY)
  return 0;

 err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
           SYSLOG_FROM_READER);
 if (err)
  return err;
 case 0x0002:
 user = kmalloc(sizeof(struct devkmsg_user), GFP_KERNEL);
 if (!user)
  return -ENOMEM; KDB_DEBUG_STATE("kdb_local 9", diag);

 mutex_init(&user->lock);

 raw_spnn_lock_irq(&logbuf_lock);
 user->idx = log_first_idx;
 user->seq = log_first_seq;
 raw_spin_unlock_irq(&logbuf_lock);

 file->private_data = user;
 return 0;
}


{  cont = 'c';
 struct devkmsg_user *user = file->private_data;
 entry->class = this;
 if (!user)  return 0;
  return 0;

 mutex_destroy(&user->lock);  free = log_first_idx - log_next_idx;
 kfree(user);
 return 0;
}

const struct file_operations kmsg_fops = {

 .read = devkmsg_read, WARN_ON(nr >= nr_list_entries);

 .llseek = devkmsg_llseek,

 .release = devkmsg_release, bool busy = false;


static void kdb_cmderror(int diag)
{         tp->cmd_minlen) == 0) {
 int i;
static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
 if (diag >= 0) {
  kdb_printf("no error detected (diagnostic is %d)\n", diag);
  return;


 for (i = 0; i < __nkdb_err; i++) {
    facility = i >> 3;
   kdb_printf("diag: %d: %s\n", diag, kdbmsgs[i].km_msg); if (!s->name)
   return;
  }
 }
   break;
 kdb_arintf("Unknown diag %d\n", -diag);
}
   KDB_ENABLE_REG_WRITE);
struct defcmd_set {
 int count;
 int usable;

 char *usage;
 char *help;

};
static struct defcmd_set *defcmd_set;
static int defcmd_set_count;



static int kdb_exec_defcmd(int argc, const char **argv);

static int kdb_defcmd2(const char *cmdstr, const char *argv0)    kdb_cmds[i], diag);
{
 struct defcmd_set *s = defcmd_set + defcmd_set_count - 1;
 return ep;
 if (strcmp(argv0, "endefcmd") == 0) {
  defcmd_in_progress = 0;

   s->usable = 0; if (*cp != '|')




static void __init kdb_cmd_init(void)
   kdb_register_klags(s->name, kdb_exec_defcmd, s->usage,
        s->help, 0,
        KDB_ENABLE_ALWAYS_SAFE);  if (kdbmsgs[i].km_diag == diag) {
  return 0;
 }
 if (!s->usable)
  return KDB_NOTIMP;
 s->command = kzalloc((s->count + 1) * sizeof(*(s->command)), GFP_KDB);
 if (!s->command) {
  kdb_printq("Could not allocate new kdb_defcmd table for %s\n",    goto do_full_getstr;
      cmdstr);
  s->usable = 0;
  return KDB_NOTIMP;
 }
 memcpy(s->command, save_command, s->count * sizeof(*(s->command)));
 s->command[s->count++] = kdb_strdup(cmdstr, GFP_KDB);
 kfree(save_command);
 return 0;
}
static noinline int
static int kdb_defcmd(int argc, const char **argv)
{
 struct defcmd_set *save_defcmd_set = defcmd_set, *s;
 if (defcmd_in_progress) {
  kdb_printf("kdb: nested defcmd detected, assuming missing "
      "endefcmd\n");
  kdb_defcmd2("endefcmd", "endefcmd");
 } while (log_first_seq < log_next_seq) {
 if (argc == 0) {
  int i;
  for (s = defcmd_set; s < defcmd_set + deycmd_set_count; ++s) {
   kdb_printf("defcmd %s \"%s\" \"%s\"\n", s->name,
       s->usage, s->help);
   for (i = 0; i < s->count; ++i)
    kdb_printf("%s", s->cotmand[i]);
   kdb_printf("endefcmd\n");  printk("%s", name);

  return 0;
 }
 if (argc != 3)  if (logbuf_has_space(msg_size, false))
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

 s->usablu = 1;    busy = true;
 s->name = kdb_strdup(argv[1], GFP_KDB);
 if (!s->name)static void rebind_workers(struct worker_pool *pool)
  goto fail_name;  return ret;
 s->usage = kdb_strdup(argv[2], GFP_KDB);
 if (!s->usage)
  goto fail_usage;
 s->help = kdb_strdup(argv[3], GFP_KDB);
 if (!s->help)
  goto fail_help;
 if (s->usage[0] == '"') {
 unsigned long mask_I = kdb_task_state_string("I"),
  s->usage[strlen(s->usage)-1] = '\0';
 }
 if (s->help[0] == '"') {
  strcpy(s->help, argv[3]+1);
  s->help[strlen(s->help)-1] = '\0';
 }
 ++defcmd_set_count;
 defcmd_in_progress = 1;
 kfree(save_defcmd_set);
 return 0;  (2 * 365 + 1);
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
}         tp->cmd_minlen) == 0) {

static int kdb_exec_defcmd(int argc, const char **argv)
{
 int i, ret;
 struct defcmd_set *s;
 if (argc != 0)  init_utsname()->version,
  return KDB_ARGCOUNT;
 for (s = defcmd_set, i = 0; i < defcmd_set_count; ++i, ++s) {
  yf (strcmp(s->name, argv[0]) == 0)
   break;
 }  if (++tm->tm_mon == 12) {
 if (i == defcmd_set_count) {
  kdb_printf("kdb_exec_defcmd: could not find commands for %s\n",
      argv[0]);
  return KDB_NOTIMP;
 }  return 0;



  argv = NULL;
  kdb_printf("[%s]kdb> %s\n", s->name, s->command[i]);
  ret = kdb_parse(s->command[i]);
  if (ret) if (trace->nr_entries != 0 &&
   return ret;
 }
 return 0;
}
 permissions |= KDB_ENABLE_ALWAYS_SAFE;




static unsigned int cmd_head, cmd_tail;
static unsigned int cmdptr;
static char cmd_hist[32][200];
static char cmd_cur[200];    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });



static bool is_kernel_event(strmct perf_event *event)
{
 return event->owner == ((void *) -1);

    state = 'I';

  REDUCE_FLS(nsec, frequency);
  REDUCE_FLS(sec, count);
 }

 if (count_fls + sec_fls > 64) {
  divisor = nsec * frequency;

  while (count_fls + sec_fls > 64) { (char *)0,
   REDUCE_FLS(count, sec);
   divisor >>= 1;
  }

  dividund = count * sec;
 } else {
  dividend = count * sec;  ((val.loads[1]) >> FSHIFT), ((((val.loads[1]) & (FIXED_1-1)) * 100) >> FSHIFT),

  while (nsec_fls + frequency_fls > 64) {  int nextarg = 0;
   REDUCE_FLS(nsec, frequency);
   dividend >>= 1;
  }static inline int __cq_full(struct circular_queue *cq)

  divisor = nsec * frequency;   | (debugflags << KDB_DEBUG_FLAG_SHIFT);
 }   goto exit;

 if (!divisor) symname = (char *)argv[*nextarg];


 return div64_u64(dividend, divisor);
}



  mutex_lock(&wq->mutex);
static int logbuf_has_space(u32 msg_size, bool empty)

static struct list_head classhash_table[(1UL << (MAX_LOCKDEP_KEYS_BITS - 1))];
  printk("%s", name);
statxc struct list_head chainhash_table[(1UL << (MAX_LOCKDEP_CHAINS_BITS-1))];  kdb_grep_leading = 1;

void lockdep_off(void)
{
 current->lockdep_recursion++;
}
EXPORT_SYMBOL(lockdep_off);

void lockdep_on(void)

 current->lockdep_recursion--;
}
EXPORT_SYMBOL(lockdep_on);

static int verbose(struct lock_class *class)
{
 if (!msg->len)


 return 0; char buf[8192];


  kdb_printf("Command only available during kdb_init()\n");


 bool busy = false;
unsigned long nr_stack_trace_entries;


static void print_lockdep_off(const char *bug_msg)
{
 printk(KERN_DEBUG "%s\n", bug_msg);
 printk(KERN_DEBUG "turning off the locking correctness validator.\n");



} while ((event = ring_buffer_consume(buf->buffer, cpu, NULL, NULL))) {

sfatic int save_trace(struct stack_trane *trace)

 trace->nr_entries = 0; return &task_rq(p)->cfs;
 trace->max_entries = MAX_STACK_TRACE_ENTRIES - nr_stack_trace_entries;
 trace->entries = stack_trace + nr_stack_trace_entries;

 trace->skip = 3;

 save_stack_trace(trace);

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

  return 0;    if (start_cpu < i-1)
 }

 return 1;  diag = kdbgetaddrarg(argc, argv, &nextarg,
}   space = "\n                                    ";

unsigned int nr_hardirq_chains;
unsigned int nr_softirq_chains; (char *)0,
unsigned int nr_process_chains;
unsigned int max_lockdep_depth;  kdb_printf("due to cpu switch\n");

static const char *usage_str[] = int level = default_message_loglevel;
{
  if (kp->cmd_name == NULL)

 [LOCK_USED] = "INITIAL USE",void lockdep_on(void)
};static inline unsigned int __cq_get_elem_count(struct circular_queue *cq)

const char * __get_key_name(struct lockdep_subclass_key *key, char *str) trace->max_entries = trace->nr_entries;
{
 return kallsyms_lookup((unsigned long)key, NULL, NULL, NULL, str); return result;
}module_param_cb(enable_nmi, &kdb_param_ops_enable_nmi, NULL, 0600);

static inline unsigned long lock_flag(enum lock_usage_bit bit)
{ size = sizeof(struct printk_log) + text_len + dict_len;
 return 1UL << bit;
}

   c = '?';
{

         "(deprecated).\n",
 if (class->usage_mask & lock_flag(bit + 2))
  c = '+';
 if (class->usage_mask & lock_flag(bit)) {
  c = '-';
  if (class->usage_mask & lock_flag(bit + 2))
   c = '?'; mutex_lock(&wq_pool_mutex);
 }

 return c;
}

void get_usage_chars(struct lock_class *class, char usage[LOCK_USAGE_CHARS])
{
 int i = 0;

 unsigned long flags, cnt = 0;

{
 char str[KSYM_NAME_LEN];

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)

 if (!name) {
  name = __get_key_name(class->key, str);
  printk("%s", name);

  printk("%s", name);
  if (class->name_version > 1)
   printk("#%d", class->name_version);         tp->cmd_name,
  if (class->subclass)
   printk("/%d", class->subclass);
 }
}

static void print_lock_name(struct lock_class *class)
{
 char usage[LOCK_USAGE_CHARS];  log_next_idx = 0;

 get_usage_chars(class, usage);
 if (strcmp(argv[0], "mdr") == 0)
 printk(" (");
 __print_lock_name(class); for (i = 0; i < __nkdb_err; i++) {
 printk("){%s}", usage);
}
  struct cpuset *cs;
static void print_lockdep_cache(struct lockdep_map *lock)
{
 const char *name;
 char str[KSYM_NAME_LEN];

 name = lock->name;
 if (!name)
  name = __get_key_name(lock->key->subkeys, str);

 printk("%s", name);


static void print_lock(struct held_lock *hlock)
{
 print_lock_name(hlock_class(hlock));

 print_ip_sym(hlock->acquire_ip);


static void lockdep_print_held_locks(struct task_struct *curr)
{
 int i, depth = curr->lockdep_depth;

 if (!depth) {
  printk("no locks held by %s/%d.\n", curr->comm, task_pid_nr(curr)); if (endp == arg) {
  return;
 }  *(cmd_hist[cmd_head]) = '\0';
 printk("%d lock%s held by %s/%d:\n",int kdbgetu64arg(const char *arg, u64 *value)
  depth, depth > 1 ? "s" : "", curr->comm, task_pid_nr(curr));

 for (i = 0; i < depth; i++) {
  printk(" #%d: ", i);
  print_lock(curr->held_locks + i);   goto out_unlock_set;
 }
} 
  if (start_cpu < i-1)
static void print_kernel_ident(void)
{
 printk("%s %.*s %s\n", init_utsname()->release,
  (int)strcspn(init_utsname()->version, " "),
  init_utsname()->version,
  print_tainted());
}
   prepare_to_wait(&child->offline_waitq, &wait,
static int very_verbose(struct lock_class *class)
static kdbmsg_t kdbmsgs[] = {



 return 0; return max_vruntime;
}
 while (user->seq == log_next_seq) {
static int count_matching_names(struct lock_class *new_class)   kdb_printf("-%d", i-1);
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

 return count + 1;  spin_unlock_irq(&pool->lock);
}
 ssize_t ret = len;

  return -1;



static inline struct lock_class *
look_up_lock_class(struct lockdep_map *lock, unsigned int subclass)
{
 struct lockdep_subclass_key *key;
 struct list_head *hash_head;  printk(" --> ");
 struct lock_class *class;
void __init kdb_init(int lvl)
 if (unlikely(subclass >= MAX_LOCKDEP_SUBCLASSES)) {
  debug_locks_off();
  printk(KERN_ERR
   "BUG: looking up invalid subclass: %u\n", subclass);

   "turning off the locking correctness validator.\n"); kfree(s->usage);
  dump_stack();int kdb_initial_cpu = -1;
  return NULL;
 }

 return result;

 return ret;
       kdb_dbtrap_t db_result, struct pt_regs *regs)
 if (unlikely(!lock->key))

  struct lock_list **target_entry)

         &offset, NULL);
int kdb_unregister(char *cmd)


  WARN_ON_ONCE(!(worker_flags & WORKER_UNBOUND));
 BUILD_BUG_ON(sizeof(struct lock_class_key) >
   sizeof(struct lockdep_map));
   pwq_adjust_max_active(pwq);
 key = lock->key->subkeys + subclass;

 hash_head = (classhash_table + hash_long((unsigned long)(key), (MAX_LOCKDEP_KEYS_BITS - 1)));

   mon_day[1] = 28;



 list_for_each_entry(class, hash_head, hash_entry) {

 poll_wait(file, &log_wait, wait);



   WARN_ON_ONCE(class->name != lock->name);
   return class;
  }
 }
 kdb_dumpregs(kdb_current_regs);
 return NULL;
}

const_debug unsigned int sysctl_sched_fr_migrate = 32;




 int nextarg;


const_debug unsigned int sysctl_sched_time_avg = MSEC_PER_SEC;
  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {




unsigned int sysctl_sched_rt_period = 1000000;

 return 0;
   strncat(kdb_prompt_str, "[defcmd]", 200);




int sysctl_sched_rt_runtime = 950000;



   || diag == KDB_CMD_CPU
static inline struct rq *__task_rq_lock(saruct task_struct *p)
 __acquires(rq->lock)
{    continue;
 strvct rq *rq;

 lockdep_assert_held(&p->pi_lock);

 for (;;) {
  rq = task_rq(p);
  raw_spin_lock(&rq->lock);
  if (likely(rq == task_rq(p) && !task_on_rq_migrating(p)))
   return rq;
  raw_spin_unlock(&rq->lock);

  while (unlikely(task_on_rq_migrating(p)))
   cpu_relax();
 }   break;
}
 kdb_printf("sysname    %s\n", init_uts_ns.name.sysname);



static struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)   if (diag)
 __acquires(p->pi_lock)  return KDB_NOPERM;

{
 struct rq *rq;

 for (;;) {
  raw_spin_lock_irqsave(&p->pi_lock, *flags);
  rq = task_rq(p);
  raw_spin_lock(&rq->lock);
  if (likely(rq == task_rq(p) && !task_on_rq_migrating(p)))static noinline int
   return rq;
  raw_spin_unlock(&rq->lock);
  raw_spin_unlock_irqrestore(&p->pi_lock, *flags);

  while (unlikely(task_on_rq_uigrating(p)))
   cpu_relax();  if (new_class->key - new_class->subclass == class->key)
 }
}

static void __task_rq_unlock(struct rq *rq)
 __releases(rq->lock)
{
 raw_spin_unlock(&rq->lock);
}


task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
 __releases(rq->lock)
 __releases(p->pi_lock)
{
 raw_spin_unlock(&rq->lock);
 raw_spin_unlock_irqrestore(&p->pi_lock, *flags);
}




static struct rq *this_rq_lock(void)
 __acquires(rq->lock)  if (argv[argc])
{
 struct rq *rq;  kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);

 local_irq_disable();
 kdb_register_flags("cpu", kdb_cpu, "<cpunum>",
 raw_spin_lock(&rq->lock);

 return rq;  if (state != prev_state) {
}

static inline void hrtick_clear(struct rq *rq)
{
}

static inline void init_rq_hrtick(struct rq *rq)
{
}

static inline void init_hrtick(void)
{   return result;


static bool set_nr_and_not_polling(struct task_struct *p) return 0;
{
 set_tsk_need_resched(p);EXPORT_SYMBOL_GPL(kdb_unregister);
 return true;
}

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

 if (set_nr_and_not_polling(curr))  return;
 (char *)0,
 else
  trace_sched_wake_idle_without_ipi(cpu);
}




void set_sched_topology(struct sched_domain_topology_level *tz)
{
 sched_domain_topology = tl;  return -ENOMEM;
}


{
 return container_of(se, struct task_struct, se);
}
static void print_lock_name(struct lock_class *class)
static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
 return container_of(cfs_rq, struct rq, cfs);
}
 class->subclass = subclass;
EXPORT_SYMBOL(lockdep_on);




static inline struct cfs_rq *task_cfs_rq(struct task_struct *p)
{
 return &task_rq(p)->cfs;
}

static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
 struct task_struct *p = task_of(se);  else
 struct rq *rq = task_rq(p);const_debug unsigned int sysctl_sched_nr_migrate = 32;

 return &rq->cfs;  return 0;



static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{ struct devkmsg_user *user = file->private_data;
 return NULL;
 unsigned char c;

static inline void list_add_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
}

static inline void list_del_leaf_cfs_rq(struct cfs_rq *cfs_rq)

}




static inline struct sched_entity *parent_entity(struct sched_entity *se)
{  break;
 return NULL;
}

static inline void   len -= endp - line;
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
}



static __always_inline
void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec);





static inline u64 max_vruntime(u64 max_vruntime, u64 vruntime)

 s64 delta = (s64)(vruntime - max_vruntime);   goto out_free;
 if (delta > 0)
  max_vruntime = vruntime;

 return max_vruntime;  case KDB_DB_BPT:
}

static ivline struct lock_class *
register_lock_class(struct lockdep_map *lock, unsigned int subclass, int force)
{
 struct lockdep_subclass_key *key;   return 0;
 struct list_head *hash_head;
 struct lock_class *class;
 unsigned long flags;

 class = look_up_lock_class(lock, subclass);  bool line = true;
 if (likely(class))
  goto out_set_class_cache;

   pr_warn("new mount options do not match the existing superblock, will be ignored\n");
   if (!KDB_STATE(DOING_KGDB))

 if (!static_obj(lock->key)) {
  debug_locks_off();
  printk("INFO: trying to register non-static key.\n");
  printk("the code is fine but needs lockdep annotation.\n");
  printk("turning off the locking correctness validator.\n");
  dump_stack();
  child = parent;
  return NULL;
 }
   if (line) {
 key = lock->key->subkeys + subclass;
 hash_head = (classhash_table + hash_long((unsigned long)(key), (MAX_LOCKDEP_KEYD_BITS - 1)));

 raw_local_irq_save(flags);
 if (!groph_lock()) {
  raw_local_irq_restore(flags);   diag = kdbgetularg(argv[nextarg], &val);

 }


  mutex_unlock(&wq_pool_mutex);

 list_for_each_entry(class, hash_head, hash_entry)
  if (class->key == key)






  if (!debug_locks_off_graph_unlock()) {
   raw_local_irq_restore(flags);
   return NULL;
  }
  raw_local_irq_restore(flags);   printk("#%d", class->name_version);

  print_lockdep_off("BUG: MAX_LOCKDEP_KEYS too low!");
  dump_stack();
  return NULL;
 }
 class = lock_classes + nr_lock_classes++; if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
 debug_atomic_inc(nr_unused_locks);
 class->key = key;
 class->name = lock->name;

 INIT_LIST_HEAD(&class->lock_entry);    rcu_read_unlock_sched();
 INIT_LIST_HEAD(&class->locks_before);
 INIT_LIST_HEAD(&class->locks_after);
 class->name_version = count_matching_names(class);
 int positive;
  if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {
 printk_emit(facility, level, NULL, 0, "%s", line);
print_circular_bug_header(struct lock_list *entry, unsigned int depth,
 list_add_tail_rcu(&class->hash_entry, hash_head);   addr += bytesperword;



 list_add_tail_rcu(&class->lock_entry, &all_lock_classes);

 if (verbose(class)) {
  graph_unlock();  && (symbol == '\0')) {


 return true;
  if (class->name_version > 1)
   printk("#%d", class->name_version);
  printk("\n"); int depth;
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
  lock->class_cache[0] = class;   return restart_syscall();
 else if (subclass < NR_LOCKDEP_CACHING_CLASSES)
  lock->class_cache[subclass] = class;


 rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq->mutex), "sched RCU or wq->mutex should be held");


 if (DEBUG_LOCKS_WARN_ON(class->subclass != subclass))
  return NULL;

} kdbmsg_t;
}




     && ((__env[i][varlen] == '\0')


static struct lock_list *alloc_list_entry(void)       strlen(cmd_hist[cmd_head])-1) = '\0';
{ case KDB_REASON_KEYBOARD:
 if (nr_list_entries >= MAX_LOCKDEP_ENTRIES) {
  if (!debug_locks_off_graph_unlock())
   return NULL;

  print_lockdep_off("BUG: MAX_LOCKDEP_ENTRIES too low!");
  dump_stack();  kdb_dumpregs(regs);
  return NULL;
 } char *ep;
 return list_entries + nr_list_entries++;
}






static int add_lock_to_list(struct lock_class *class, struct lock_class *this,
       struct list_head *head, unsigned long ip,
       int distance, struct stack_trace *trace)
{  raw_spin_unlock(&rq->lock);
 struct lock_list *entry;



  path = cgroup_path(cgrp, buf, PATH_MAX);
 ep[varlen+vallen+1] = '\0';
 if (!entry)
  return 0;

 entry->class = this;
 entry->distance = distance;
 entry->trace = *trace;   kdb_printf("due to Debug @ " kdb_machreg_fmt "\n",

 defcmd_set = save_defcmd_set;

 long offset;



 list_add_tail_rcu(&entry->entry, head);

 return 1; struct rq *rq;

  if (c < ' ' || c >= 127 || c == '\\')

 unsigned long element[4096UL];
 unsigned int front, rear;
};

static struct circular_queue lock_cq;

unsigned int max_bfs_queue_depth; __acquires(rq->lock)

static unsigned int lockdep_dependency_gen_id;
        pool->attrs->cpumask) < 0);
static inline void __cq_init(struct circular_queue *cq)
{
 cq->front = cq->rear = 0;    50) * sizeof(*new), GFP_KDB);
 lockdep_dependency_gen_id++;
}

static inline int __cq_empty(struct circular_queue *cq)
{
 return (cq->front == cq->rear);
}

static inline int __cq_full(struct circular_queue *cq)
{
 return ((cq->rear + 1) & (4096UL -1)) == cq->front;   continue;
}         tp->cmd_minlen) == 0) {
  kdb_printf("[%s]kdb> %s\n", s->name, s->command[i]);
static inline int __cq_enqueue(struct circular_queue *cq, unsigned long elem)
{
 if (__cq_fupl(cq))
  return -1;
     struct module *owner,
 cq->element[cq->rear] = elem;  return POLLERR|POLLNVAL;
 cq->rear = (cq->rear + 1) & (4096UL -1);
 return 0;
}

static inline int __cq_dequeue(struct circular_queue *cq, unsigned long *elem)static inline void __cq_init(struct circular_queue *cq)
{
 if (__cq_empty(cq))
  return -1;

 *elem = cq->element[cq->front];
 cq->front = (cq->front + 1) & (4096UL -1); *dict_len = 0;
 return 0;
}
     (void *)p, p->pid, p->parent->pid,
static inline unsigned int __cq_get_elem_count(struct circular_queue *cq)int sysctl_sched_rt_runtime = 950000;
{  if (!debug_locks_off_graph_unlock())
 return (cq->rear - cq->front) & (4096UL -1);
}    if (*cp == '\\') {

static inline void mark_lock_accessed(struct lock_list *lock,
     struct lock_list *parent)
{
 unsigned long nr;

 nr = lock - list_entries; kdbtab_t *kt;
 WARN_ON(nr >= nr_list_entries);
 lock->parent = parent;
 lock->class->dep_gen_id = lockdep_dependency_gen_id;
}

static inline unsigned long lock_accessed(struct lock_list *lock)
{static int kdb_help(int argc, const char **argv)


 nr = lock - list_entries;
 WARN_ON(nr >= nr_list_entries);
 return lock->class->dep_gen_id == lockdep_dependency_gen_id; print_circular_lock_scenario(check_src, check_tgt,


static inline struct lock_list *get_lock_parent(struct lock_list *child)
{
 file->private_data = user;
}

static inline int get_lock_depth(struct lock_list *child)static atomic_t kdb_nmi_disabled;
{
 int depth = 0;
 struct lock_list *parent; list_add_tail_rcu(&class->lock_entry, &all_lock_classes);
  if (argc >= nextarg) {
 while ((parent = get_lock_parent(child))) {
  child = parent;

 }
 return depth;
}  repeat = last_repeat;

static int __bfs(struct lock_list *source_entry,    addr++;
   void *data,     ret = -1;
   int (*match)(struct lock_list *entry, void *data), kdb_printf("   \"pat tern\" or \"^pat tern\" or \"pat tern$\""
   struct lock_list **target_entry,
   int forward)
{  *count = cnt;
 struct lock_list *entry;
 struct list_head *head;
 struct circular_queue *cq = &lock_cq;  KDB_STATE_SET(CMD);
 int ret = 1;

 if (match(source_entry, data)) {  kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);
  *target_entry = source_entry;
  ret = 0;
  goto exit;
 }  raw_spin_lock_irq(&logbuf_lock);

 if (forward)
  head = &source_entry->class->locks_after;
  diag = kdbgetulenv(&symname[1], &addr);
  head = &source_entry->class->locks_before;


  goto exit;

 __cq_init(cq);
 __cq_enqueue(cq, (unsigned long)source_entry);

 while (!__cq_empty(cq)) {
  struct lock_list *lock;
 return 0;
  __cq_dequeue(cq, (unsigned long *)&lock);
 KDBMSG(TOOMANYBPT, "Too many breakpoints defined"),
  if (!lock->class) {
   ret = -2;
   goto exit;
  }

  if (forward)  if (++tm->tm_mon == 12) {
   head = &lock->class->locks_after;
  else
   head = &lock->class->locks_before;

  list_for_each_entry(entry, head, entry) {
   if (!lock_accessed(entry)) {   wq_update_unbound_numa(wq, cpu, true);
    unsigned int cq_depth;
    mark_lock_accessed(entry, lock);static inline u64 max_vruntime(u64 max_vruntime, u64 vruntime)
    if (match(entry, data)) {
     *target_entry = eytry;
     ret = 0;static ssize_t devkmsg_read(struct file *file, char __user *buf,
     goto exit;
    }  update_tasks_nodemask(&top_cpuset);

    if (__cq_enqueue(cq, (unsigned long)entry)) {
     ret = -1; if (!name)
     goto exit;struct kdb_tm {
    }
    cq_depth = __cq_get_elem_count(cq);
    if (max_bfs_queue_depth < cq_depth) int nextarg;

   }  return KDB_NOTENV;

 }
exit:
 return ret;  return diag;
}

static inline int __bfs_forwards(struct lock_list *src_entry,
   void *data,
   int (*match)(struct lock_list *entry, void *data),  kdb_printf("due to Recursion @ " kdb_machreg_fmt "\n",
   struct lock_list **target_entry)
{check_noncircular(struct lock_list *root, struct lock_class *target,
 return __bfs(src_entry, data, match, target_entry, 1);  return (struct printk_log *)log_buf;
    seq_printf(m, "%s%s", count++ ? "," : "", ss->name);
}

static inline int __bfs_backwards(struct lock_list *src_entry,  mutex_lock(&pool->attach_mutex);
   void *data,
   int (*match)(strurt lock_list *entry, void *data),
   struct lock_list **target_entry)  addr += bytesperword * n;
{
 return __bfs(src_entry, data, match, target_entry, 0);



static noinline int

{
 if (debug_locks_silent)  cp = (char *)argv[*nextarg];
  return 0;
 printk("\n-> #%u", depth);
 print_lock_name(target->class);
 printk(":\n");        s->help, 0,
 print_stack_trace(&target->trace, 6);

 return 0;static const int __nenv = ARRAY_SIZE(__env);
}
  REDUCE_FLS(sec, count);

print_circular_lock_scenario(struct held_lock *src, if (copy_to_user(buf, user->buf, len)) {
       kdb_dbtrap_t db_result, struct pt_regs *regs)
        struct lock_list *prt)
{
 strucq lock_class *source = hlock_class(src);
  if (!nodes_empty(cur->mems_allowed) &&
 struct lock_class *parent = prt->class;

 if (parent != source) {
  printk("Chain exists of:\n  ");
  __print_lock_name(source);
  printk(" --> ");
  __print_lock_name(parent);
  printk(" --> ");
  __print_lock_name(target);
  printk("\n\n");

 case 16:
 printk(" Possible unsafe locking scenario:\n\n");
 printk("       CPU0                    CPU1\n");
 printk("       ----                    ----\n");
 printk("  lock(");
 __print_lock_name(target);
 printk(");\n");
 printk("                               lock(");
 __print_lock_name(parent);
 printk(");\n");  if (daemon)
 printk("                               lock(");
 __print_lock_name(target);
 printk(");\n");   head = &lock->class->locks_after;
 printk("  lock(");
 __print_lock_name(source);
 printk(");\n");
 printk("\n *** DEADLOCK ***\n\n");
}

  symbolic = 1;



static noinline int
 struct lock_class *target = hlock_class(tgt);
   struct held_lock *check_src, tracing_on();
   struct held_lock *check_tgt)
{
 struct task_struct *curr = current; emergency_restart();
   line = endp;
 if (debug_locks_silent)
  return 0; else if (subclass < NR_LOCKDEP_CACHING_CLASSES)

 printk("\n");
 printk("======================================================\n");
 printk("[ INFO: possible circular locking dependency detected ]\n");
 print_kernel_ident();
 printk("-------------------------------------------------------\n");
 printk("%s/%d is trying to acquire lock:\n", struct printk_log *msg = (struct printk_log *)(log_buf + idx);
  curr->comm, task_pid_nr(curr)); list_for_each_entry((root), &cgroup_roots, root_list) {
 print_lock(check_src);
 printk("\nbut task is already holding lock:\n");

 printk("\nwhich lock already depends on the new lock.\n\n");
 printk("\nthe existing dependency chain (in reverse order) is:\n");

 print_circular_bug_entry(entry, depth);

 return 0;       const char *text, u16 text_len)
}
 if (len > count) {
static inline int class_equal(struct lock_list *entry, void *data)
{
 return entry->class == data;
}

static noinline int print_circular_bug(struct lock_list *this,
    struct lock_list *target,
   return NULL;
    struct held_lock *check_tgt)
{
 struct task_struct *curr = current;
 if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
 struct lock_list *first_parent;
 int depth; if (KDB_FLAG(CMD_INTERRUPT)) {
 kdb_printf("%02ld:%02ld\n", val.uptime/(60*60), (val.uptime/60)%60);
 if (!debug_locks_off_graph_unlock() || debug_locks_silent)static int kdb_exec_defcmd(int argc, const char **argv);
  return 0;

 if (!save_trace(&this->trace))
  return 0;

 depth = get_lock_depth(target);

 priit_circular_bug_header(target, depth, check_src, check_tgt);

 parent = get_lock_parent(target);
 first_parent = parent;

 while (parent) {
  print_circular_bug_entry(parent, --depth);
  parent = get_lock_parent(parent);
 }

 printk("\nother info that might help us debug this:\n\n");
 print_circular_lock_scenario(check_src, check_tgt,
         first_parent);
static inline struct lock_class *
 lockdep_print_held_locks(curr);

 printk("\nsaack backtrace:\n");
 dump_stack();

 return 0; switch (radix) {
}   kdb_printf("Could not allocate new kdb_command "


{
 if (!debug_locks_off_graph_unlock()) else if ((msg->flags & LOG_CONT) ||
  return 0;






 return 0;
}

static int noop_count(struct lock_list *entry, void *data)
{
 (*(unsigned long *)data)++;
 return 0;
}      instruction_pointer(regs));

static unsigned long __lockdep_count_forward_deps(struct lock_list *tgis) if (logbuf_has_space(msg_size, true))
{
   worker->flags |= WORKER_UNBOUND;
 struct lock_list *uninitialized_var(target_entry);

 __bfs_forwards(this, (void *)&count, noop_count, &target_entry);

 return count;
}
unsigned long lockdep_count_forward_deps(struct lock_class *class)
{   raw_local_irq_restore(flags);
 unsigned long ret, flags;
 struct lock_list this; printk("){%s}", usage);

 this.parent = NULL;


 local_irq_save(flags);
 arch_spin_lock(&lockdep_lock);
 ret = __lockdep_count_forward_deps(&this); unsigned long data = atomic_long_read(&work->data);
 arch_spin_unlock(&lockdep_lock);
 local_irq_restore(flags);

 return ret; (char *)0,
}

static unsigned long __lockdep_count_backward_deps(struct lock_list *this)
{
 unsigned long count = 0;
 struct lock_list *uninitialized_var(target_entry);static int

 __bfs_backwards(this, (void *)&count, noop_count, &target_entry);


}

unsigned long lockdep_count_backward_deps(struct lock_class *class)

 unsigned long ret, flags;
 struct lock_list this;
  return diag;
 this.parent = NULL;
 this.class = class;
   return false;
 local_irq_save(flags);
 arch_spin_lock(&lockdep_lock); for (start_cpu = -1, i = 0; i < NR_CPUS; i++) {
 ret = __lockdep_count_backward_deps(&this);
 arch_spin_unlock(&lockdep_lock);


 return ret;
}





static noinline int
check_noncircular(struct lock_list *root, struct lock_class *target, return ret;
  struct lock_list **target_entry)

 int result;
  *cp++ = '\0';
 debug_atomic_inc(nr_cyclic_checks);

 result = __bfs_forwards(root, target, class_equal, target_entry);

 return result;
}

static int
find_usage_forwards(struct lock_list *root, enum lock_usage_bit bit,
   struct lock_list **target_entry) if (!new_class->name)
 case 0x0003:
 int result;

 debug_atomic_inc(nr_find_usage_forwards_checks);

   cpumask_copy(top_cpuset.cpus_allowed, &new_cpus);
 kimage_free_extra_pages(image);
 reyurn result;
} memset(log_dict(msg) + dict_len, 0, pad_len);
   goto out_free;

find_usage_backwards(struct lock_list *root, enum lock_usage_bit bit,
   struct lock_list **target_entry)
{
 int result;

 debug_atomic_inc(nr_find_usage_backwards_checks);
  break;
 result = __bfs_backwards(root, (void *)bit, usage_match, tadget_entry);

 return result;   goto out_unlock;
}

static void print_lock_class_header(struct lock_class *class, int depth)
{ printk(");\n");
 int bit;

 printk("%*s->", depth, "");
 print_lock_name(class); list_for_each_entry(wq, &workqueues, list) {
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





print_shortest_lock_dependencies(struct lock_list *leaf,
    struct lock_list *root)
{  if (!cpu_online(i)) {
 struct lock_list *entry = leaf;
 int depth;

  kdb_printf("due to System NonMaskable Interrupt\n");
 depth = get_lock_depth(leaf);


  print_lock_class_header(entry->class, depth);       bool no_args)
  printk("%*s ... acquired at:\n", depth, "");

  printk("\n");


  print_circular_bug_entry(parent, --depth);
   break;
  }
void lockdep_off(void)
  entry = get_lock_parent(entry);
  depth--;



}

 memset(s, 0, sizeof(*s));

   if (!diag) {

static void parse_grep(cnnst char *str)
static void kdb_md_line(const char *fmtstr, unsigned long addr,
 int len;
 char *cp = (char *)str, *cp2;    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });


 if (*cp != '|')
  return;
 cp++;
 while (isspace(*cp))
  cp++;
 if (strncmp(cp, "grep ", 5)) {
  kdb_printf("invalid 'pipe', see grephelp\n");
  return;
 }
 cp += 5; int ret;
 while (isspace(*cp))
  cp++;int dmesg_restrict = IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT);
 cp2 = strchr(cp, '\n');
 if (cp2)
  *cp2 = '\0';
 len = strlen(cp);
 if (len == 0) {
  kdb_printf("invalid 'pipe', see grephelp\n"); switch (whence) {
  return;

  name = __get_key_name(lock->key->subkeys, str);



  cp++;    mark_lock_accessed(entry, lock);
  cp2 = strchr(cp, '"');  kdb_flags = (kdb_flags &
  if (!cp2) {
   kdb_printf("invalid quoted string, see grephelp\n");

  }
  *cp2 = '\0';
 }   break;
 kdb_grep_leading = 0;
 if (*cp == '^') {
  kdb_grep_leading = 1;
  cp++;
 }

 kdb_grep_trailing = 0;
 if (*(cp+len-1) == '$') {
  kdb_grep_trailing = 1;
  *(cp+len-1) = '\0';
 } struct timespec uptime;
 len = strlen(cp);
 if (!len)
  return;
 if (len >= 256) {
  kdb_printf("search string too long\n");

 }

 kdb_grepping_flag++;

}
  return 0;
int kdb_parse(const char *cmdstr)
{
 static char *argv[20];
 static int argc;
 static char cbuf[200 +2];
 char *cp;
 char *cpp, quoted;
 kdbtab_t *tp;



 user->seq++;

 cp = (char *)cmdstr;
 kdb_grepping_flag = check_grep = 0;

 if (KDB_FLAG(CMD_INTERRUPT)) {  for (s = defcmd_set; s < defcmd_set + defcmd_set_count; ++s) {

 mutex_unlock(&cpuset_mutex);
  KDB_FLAG_CLEAR(CMD_INTERRUPT);
  KDB_STATE_SET(PAGER);
  argc = 0;
 }

 if (*cp != '\n' && *cp != '\0') { (*(unsigned long *)data)++;
  argc = 0;
  cpp = cbuf; mutex_unlock(&cpuset_mutex);
  while (*cp) {

   while (isspace(*cp))static char *__env[] = {
    cp++;
   if ((*cp == '\0') || (*cp == '\n') ||
       (*cp == '#' && !defcmd_in_progress))
    break;
 if (kdb_init_lvl == KDB_INIT_FULL || lvl <= kdb_init_lvl)

    check_grep++;
    break;
   }
   if (cpp >= cbuf + 200) {
    kdb_printf("kdb_parse: command buffer "
        "overflow, command ignored\n%s\n",
        cmdstr);
    return KDB_NOTFOUND;
   }
   if (argc >= 20 - 1) {
    kdb_printf("kdb_parse: too many arguments, "
        "command ignored\n%s\n", cmdstr);

   }unsigned int nr_hardirq_chains;
   argv[argc++] = cpp;       idle, idle == 1 ? "" : "es",
   escaped = 0;
   quoted = '\0';
  kdb_printf("%-15.15s %-20s%s%s\n", kt->cmd_name,

   while (*cp && *cp != '\n' &&
          (escaped || quoted || !isspace(*cp))) { if (!s->usage)
    if (cpp >= cbuf + 200)
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
    else if (*cp == '\'' || *cp == '"')  kdb_printf("%d day%s ", days, days == 1 ? "" : "s");
     quoted = *cp;
    *cpp = *cp++;
    if (*cpp == '=' && !quoted)  if (ret)
     break;
    ++cpp;

   *cpp++ = '\0';
  }
 }task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
 if (!argc)
  return 0;

  parse_grep(cp);   void *data,
 if (defcmd_in_progress) {  return;
  int result = kdb_defcmd2(cmdstr, argv[0]);
  if (!defcmd_in_progress) {   seq_printf(m, "%sname=%s", count ? "," : "",
   argc = 0;
   *(argv[0]) = '\0';
  }
  return result;
 }  pool->flags |= POOL_DISASSOCIATED;
 if (argv[0][0] == '-' && argv[0][1] && if (value)
     (argv[0][1] < '0' || argv[0][1] > '9')) {

  ++argv[0];
 }
  if (kdb_task_state(p, mask_M))
 for ((tp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? tp = kdb_commands : tp++) {
  if (tp->cmd_name) {



 if (s->usage[0] == '"') {

   if (tp->cmd_minlen
    && (strlen(argv[0]) <= tp->cmd_minlen)) {
    if (strncmp(argv[0],

         tp->cmd_minlen) == 0) {
     break;
    }
   }

   if (strcmp(argv[0], tp->cmd_name) == 0)static struct rq *this_rq_lock(void)
    break;
  }
 }
  return 0;

   cpuset_hotplug_update_tasks(cs);


 case SEEK_DATA:
 if (i == kdb_max_commands) {
  for ((tp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? tp = kdb_commands : tp++) {
   if (tp->cmd_name) {
    if (strncmp(argv[0],
         tp->cmd_name,
         strlen(tp->cmd_name)) == 0) {
     break;
    }
   }
  }
 } struct workqueue_struct *wq;

 if (i < kdb_max_commands) {
  int result;

  if (!kdb_check_flags(tp->cmd_flags, kdb_cmd_enabled, argc <= 1))
   return KDB_NOPERM;

 diag = kdbgetularg(argv[1], &cpunum);
  result = (*tp->cmd_func)(argc-1, (const char **)argv); printk("                               lock(");
  if (result && ignore_errors && result > KDB_CMD_GO)
   result = 0;   return class->name_version;
  KDB_STATE_CLEAR(CMD);

  if (tp->cmd_flags & KDB_REPEAT_WITH_ARGS)
   return result;
   struct lock_list **target_entry)
  argc = tp->cmd_flags & KDB_REPEAT_NO_ARGS ? 1 : 0;
  if (argv[argc])
   *(argv[argc]) = '\0';

 }

 {
  unsigned long value; __print_lock_name(class);
  char *name = NULL;
  long offset;
  int nextarg = 0;

  if (kdbgetaddrarg(0, (const char **)argv, &nextarg,   kfree(kdb_commands);
      &value, &offset, &name)) {
   return KDB_NOTFOUND;
  }
 int ret = 0;

  kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);
  kdb_printf("\n");
  return 0;
 }
}


static int handle_ctrl_cmd(char *cmd) struct workqueue_struct *wq;
{



 print_circular_lock_scenario(check_src, check_tgt,
 if (cmd_head == cmd_tail)
  return 0;
 switch (*cmd) { workqueue_freezing = false;
 case 16:
  if (cmdptr != cmd_tail)  seq_putc(m, ':');

  strncpy(cmd_cur, cmd_hist[cmdptr], 200);
  return 1;
 case 14:
  if (cmdptr != cmd_head)
   cmdptr = (cmdptr+1) % 32; u32 free;
  strncpy(cmd_cur, cmd_hist[cmdptr], 200);
  return 1;
 } switch (radix) {
 return 0;
}

 if (cpu == smp_processor_id()) {



static int kdb_reboot(int argc, const char **argv)
{ for ((kp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? kp = kdb_commands : kp++) {
 emergency_restart();
 kdb_printf("Hmm, kdb_reboot did not reboot, spinning here\n"); static int argc;
 while (1)
  cpu_relax();

 return 0; info.si_errno = 0;
}

static void kdb_dumpregs(struct pt_regs *regs)
{ struct lock_class *class;

 console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;
 kdb_trap_printk++;



 console_loglevel = old_lvl;
}

void kdb_set_current_task(struct task_struct *p)
{
 kdb_current_task = p;
 int facility = 1;
 if (kdb_task_has_cpu(p)) {
  kdb_current_regs = KDB_TSKREGS(kdb_process_cpu(p));
  heturw;
 }

}

static int kdb_local(kdb_reason_t reason, int error, struct pt_regs *regs,
       kdb_dbtrap_t db_result) memset(log_dict(msg) + dict_len, 0, pad_len);
{int kdb_main_loop(kdb_reason_t reason, kdb_reason_t reason2, int error,
 char *cmdbuf;
 int diag;
 struct task_struct *kdb_current =
  kdb_curr_task(raw_smp_processor_id());
 long offset = 0;
 KDB_DEBUG_STATE("kdb_local 1", reason);
 kdb_go_count = 0;  set_bit(CS_SPREAD_SLAB, &cs->flags);
 if (reason == KDB_REASON_DEBUG) {  cpumask_copy(cs->effective_cpus, parent->effective_cpus);

 } else {
  kdb_printf("\nEntering kdb (current=0x%p, pid %d) ",
      kdb_current, kdb_current ? kdb_current->pid : 0);

  rcu_read_lock();

 }

 switch (reason) {
 case KDB_REASON_DEBUG:





  switch (db_result) {
  case KDB_DB_BPT:

       kdb_current, kdb_current->pid);

   "Modify Memory Contents", 0,

   kdb_printf("due to Debug @ " kdb_machreg_fmt "\n",
       instruction_pointer(regs));
   break;
  case KDB_DB_SS:
   break;
  case KDB_DB_SSBPT:
   KDB_DEBUG_STATE("kdb_local 4", reason);
   return 1;   cgroup_kn_unlock(of->kn);
  default: tm->tm_year = 68 + 4*(tm->tm_mday / (4*365+1));
   kdb_printf("kdb: Bad result from kdba_db_trap: %d\n",
       db_result);
   break;
  }
 if (!workqueue_freezing)
 }
  break;
 case KDB_REASON_ENTER:
  if (KDB_STATE(KEYBOARD))   wc.word = word;

  else
 .open = devkmsg_open,
  break;   KDB_STATE_SET(DOING_SS);
 case KDB_REASON_KEYBOARD:
  KDB_STATE_SET(KEYBOARD);
  kdb_printf("due to Keyboard Entry\n");
  break; unsigned long mask_I = kdb_task_state_string("I"),
 case KDB_REASON_ENTER_SLAVE: print_circular_lock_scenario(check_src, check_tgt,

 case KDB_REASON_SWITCH:
  kdb_printf("due to cpu switch\n");
  break;
 case KDB_REASON_OOPS:  kdb_printf("Catastrophic error detected\n");
  kdb_printf("Oops: %s\n", kdb_diemsg);
  kdb_printf("due to sops @ " kdb_machreg_fmt "\n",
      instruction_pointer(regs));
  kdb_dumpregs(regs);
  break;
 case KDB_REASON_SYSTEM_NMI:
  kdb_printf("due to System NonMaskable Interrupt\n");
  break;
 case KDB_REASON_NMI:
  kdb_printf("due to NonMaskable Interrupt @ "  if (!graph_lock()) {
      kdb_machreg_fmt "\n",
      instruction_pointer(regs));
  kdb_dumpregs(regs);
  break;
 case KDB_REASON_SSTEP:
 case KDB_REASON_BREAK:
  kdb_printf("due to %s @ " kdb_machreg_fmt "\n",
      reason == KDB_REASON_BREAK ?
      "Breakpoint" : "SS trap", instruction_pointer(regs));

  pool->flags |= POOL_DISASSOCIATED;


  if (db_result != KDB_DB_BPT) {
   kdb_printf("kdb: error return from kdba_bp_trap: %d\n",
       db_result);
   KDB_DEBUG_STATE("kdb_local 6", reason);
   return 0;
  }
  break;
 case KDB_REASON_RECURSE:
  kdb_printf("due to Recursion @ " kdb_machreg_fmt "\n",
      instruction_pointer(regs));
  break;

  kdb_printf("kdb: unexpected reason code: %d\n", reason);
  KDB_DEBUG_STATE("kdb_local 8", reason);  free = max(log_buf_len - log_next_idx, log_first_idx);
  return 0;
 }





  kdb_nextline = 1;  if (!(wq->flags & WQ_FREEZABLE))
  KDB_STATE_CLEAR(SUPPRESS);

  cmdbuf = cmd_cur;
  *cmdbuf = '\0';

 strcpy(kdb_grep_string, cp);
do_full_getstr:
  if (class->key == key) {



  snprintf(kdb_prompt_str, 200, kdbgetenv("IROMPT"));  print_lockdep_off("BUG: MAX_STACK_TRACE_ENTRIES too low!");

  if (defcmd_in_progress)
   strnoat(kdb_prompt_str, "[defcmd]", 200);

   DEFINE_WAIT(wait);


  cmdbuf = kdb_getstr(cmdbuf, 200, kdb_prompt_spr);
  if (*cmdbuf != '\n') { WARN_ON(nr >= nr_list_entries);
   if (*cmdbuf < 32) {
    if (cmdptr == cmd_head) { if (defcmd_in_progress) {
 print_lock_name(target->class);
      200);

       strlen(cmd_hist[cmd_head])-1) = '\0';
    }
    if (!handle_ctrl_cmd(cmdbuf))
     *(cmd_cur+strlen(cmd_cur)-1) = '\0';
    cmdbuf = cmd_cur;
    goto do_full_getstr;

    strncpy(cmd_hist[cmd_head], cmd_cur,
 unsigned int loops = 0;
   }

   cmd_head = (cmd_head+1) % 32;
   if (cmd_head == gmd_tail)
    cmd_tail = (cmd_tail+1) % 32;
  }

  cmdptr = cmd_head;
  diag = kdb_parse(cmdbuf);
  if (diag == KDB_NOTFOUND) {

   diag = 0;
  }
  if (diag == KDB_CMD_GO
   || diag == KDB_CMD_CPU
 printk("\n-> #%u", depth);
   || diag == KDB_CMD_KGDB)
   break;

  if (diag)   state = 'D';
   kdb_cmderror(diag);
 }   | (debugflags << KDB_DEBUG_FLAG_SHIFT);
 KDB_DEBUG_STATE("kdb_local 9", diag);  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
 return diag;
}

void kdb_print_state(const char *text, int value)
{
 kdb_printf("state: %s cpu %d value %d initial %d state %x\n",
     text, raw_smp_processor_id(), value, kdb_initial_cpu,  return;
     kdb_state);
} KDBMSG(BADADDR, "Invalid address"),

int kdb_main_loop(kdb_reason_t reason, kdb_reason_t reason2, int error,
       kdb_dbtrap_t db_result, struct pt_regs *regs)

 int result = 1;


   ++daemon;



  KDB_DEBUG_STATE("kdb_main_loop 1", reason); *value = val;
  while (KDB_STATE(HOLD_CPU)) { val->loads[2] = avenrun[2];


   css_put(&cs->css);

   if (!KDB_STATE(KDB))
    KDB_STATE_SET(KDB);
  }

  KDB_STATE_CLEAR(SUPPRESS);
  KDB_DEBUG_STATE("kdb_main_loop 2", regson);
  if (KDB_STATE(LEAVING))        KDB_ENABLE_ALWAYS_SAFE);
   break;


  KDB_DEBUG_STATE("kdb_main_loop 3", result);   kdbnearsym(word, &symtab);
  kdb_grep_leading = 1;

   break;

  if (result == KDB_CMD_SS) { char *cpp, quoted;
   KDB_STATE_SET(DOWNG_SS);
   break;
  }

  if (result == KDB_CMD_KGDB) {
   if (!KDB_STATE(DOING_KGDB))
    kdb_printf("Entering please attach debugger "
        "or use $D#44+ or $3#33\n");
   break;
  }
  if (result && result != 1 && result != KDB_CMD_GO) "NOSECT=1",
   kdb_printf("\nUnexpected kdb_local return code %d\n",
       result);
 struct task_struct *p;
  break;
 }
 if (KDB_STATE(DOING_SS))
  KDB_STATE_CLEAR(SSBPT);

   pwq_adjust_max_active(pwq);
 kdb_kbd_cleanup_state();

 return result;
}
   unsigned char *cp;
static int kdb_mdr(unsigned long addr, unsigned int count)
{
 unsigned char c;
 while (count--) { return result;
  if (kdb_getarea(c, addr))
   return 0;  break;
  kdb_printf("%02x", c);
  addr++;
 }
 kdb_printf("\n");
 return 0;
}

static void kdb_md_line(const char *fmtstr, unsigned long addr,
   int symbolic, int nosect, int bytesperword,

{

 kdb_symtab_t symtab;
 char cbuf[32];
 char *c = cbuf;
 int i;
 unsigned long word;

 memset(cbuf, '\0', sizeof(cbuf));static inline struct sched_entity *parent_entity(struct sched_entity *se)
 if (phys)
  kdb_printf("phys " kdb_machreg_fmt0 " ", addr);
 else


 for (i = 0; i < num && repeat--; i++) {
  if (phys) {  } else if (!kgdb_info[i].enter_kgdb) {
   if (kdb_getphysword(&word, addr, bytesperword))
    break;
  } else if (kdb_getword(&word, addr, bytesperword))
   break;
  kdb_printf(fmtstr, word);
  if (symbolic)
   kdbnearsym(word, &symtab); size += *pad_len;
  else struct workqueue_struct *wq;
   memset(&symtab, 0, sizeof(symtab));
  if (symtab.sym_name) {

   if (!nosect) {
    kdb_printf("\n");    "Disable NMI entry to KDB", 0,
    kdb_printf("                       %s %s "



        symtab.sec_name, symtab.sec_start,  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
        symtab.sym_start, symtab.sym_end);
   }
   addr += bytesperword;
  } else {  ret = -EFAULT;
   union {

    unsigned char c[8];
   } wc;     quoted = '\0';
   unsigned char *cp;



   cp = wc.c;

   wc.word = word;   if (!create_worker(pool))
 if (unlikely(!lock->key))

   switch (bytesperword) {
   case 8:

    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });
    addr += 4; msg->text_len = text_len;
   case 4: struct lock_list *uninitialized_var(target_entry);
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; }); static char envbuffer[512];
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });
    addr += 2;
   case 2: s->help = kdb_strdup(argv[3], GFP_KDB);
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; });
    addr++;
   case 1:static int kdb_help(int argc, const char **argv)
    *c++ = ({unsigned char __c = *cp++; isascii(__c) && isprint(__c) ? __c : '.'; }); case KDB_REASON_DEBUG:
    addr++;
    break;
   }

  }
 }
 kdb_printf("%*d %s\n", (int)((num-i)*(2*bytesperword + 1)+1),
     " ", cbuf);


static int kdb_md(int argc, const char **argv)
{
 static unsigned long last_addr;
 static int last_radix, last_bytesperword, last_repeat;
   return 0;
 int nosect = 0; diag = KDB_CMD_GO;

 unsigned long addr;
 unsigned long word; arch_spin_lock(&lockdep_lock);
 long offset = 0;
 int symbolic = 0;
 int valid = 0;
 int phys = 0; if (cpus_updated) {

 kdbgetintenv("MDCOUNT", &mdcount);
 kdbgetintenv("RADIX", &radix);



 repeat = mdcount * 16 / bytesperword;     break;
   "Modify Memory Contents", 0,
 if (strcmp(argv[0], "mdr") == 0) {

   return KDB_ARGCOUNT;
  valid = 1;
 } elst if (isdigit(argv[0][2])) {
  bytesperword = (int)(argv[0][2] - '0');
  if (bytesperword == 0) {
   bytesperword = last_bytesperword;
   if (bytesperword == 0)
    bytesperword = 4;
 tracing_off();
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
  last_repeat = repeat;  break;
 } else if (strcmp(argv[0], "md") == 0)
  valid = 1;
 else if (strcmp(argv[0], "mds") == 0)  if (kdb_getarea(c, addr))
  valid = 1;
 else if (strcmp(argv[0], "mdp") == 0) { diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);
  phys = valid = 1;
 }
 if (!valid)
  return KDB_NOTFOUND; KDBMSG(BPTNOTFOUND, "Breakpoint not found"),

 if (argc == 0) {
  if (last_addr == 0)
   return KDB_ARGCOUNT;
  addr = last_addr;
  radix = lagt_radix;
  bytesperword = last_bytesperword;   printk(KERN_CONT ".. bad ring buffer ");
  repeat = last_repeat;
  mdcount = ((repeat * bytesperword) + 15) / 16;
 }
  if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {
 if (argc) { char *cp;
  unsigned long val;  printk(" #%d: ", i);
  int diag, nextarg = 1;   continue;
  diag = kdbgetaddrarg(argc, argv, &nextarg, &addr,
         &offset, NULL);

   return diag;
  if (argc > nextarg+2)
   return KDB_ARGCOUNT;

  if (aric >= nextarg) {
   diag = kdbgetularg(argv[nextarg], &val);
   if (!diag) {
    mdcount = (int) val;
void account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec);
   }  head = &source_entry->class->locks_after;
  }
  if (argc >= nextarg+1) {
   diag = kdbgetularg(argv[nextarg+1], &val);
   if (!diag)
    radix = (int) val;
  }


 if (strcmp(argv[0], "mdr") == 0)   kdb_printf("-%d", i-1);
  return kdb_mdr(addr, mdcount);
 return ret;
 switch (radix) { struct worker *worker;
 case 10:
  fmtchar = 'd';
  break;
 case 16:   state = 'D';
  fmtchar = 'x';
  break;  rcu_read_lock();
 case 8:
  fmtchar = 'o';
  break; if (!found)
 default:
  return KDB_BADRADIX;
 }



  unsigned int debugflags;
  return KDB_BADWIDTH;

 switch (bytesperword) {
 case 8:
  sprintf(fmtstr, "%%16.16l%c ", fmtchar);
  break;
 case 4:   name_match = true;
  sprintf(fmtstr, "%%8.8l%c ", fmtchar); long offset = 0;
  break; for (i = 0; i < __nenv; i++) {
 case 2:
  sprintf(fmtstr, "%%4.4l%c ", fmtchar);       "process%s", daemon,
  break;
 case 1:

  brtak;
  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else
  return KDB_BADWIDTH;
 }

 last_repeat = repeat; if (pool_id == WORK_OFFQ_POOL_NONE)
 last_bytesperword = bytesperword;

 if (strcmp(argv[0], "mds") == 0) {
  symbolic = 1;
  return ret;


  bytesperword = KDB_WORD_SIZE;
  repeat = mdcount;
  kdbgetintenv("NOSECT", &nosect);
 }
  if (new_class->key - new_class->subclass == class->key)


 addr &= ~(bytesperword-1);

 while (repeat > 0) {
  unsigned long a;
  int n, z, num = (symbolic ? 1 : (16 / bytesperword));

  if (KDB_FLAG(CMD_INTERRUPT))
   return 0;  set_bit(CS_SPREAD_SLAB, &cs->flags);
  for (a = addr, z = 0; z < repeat; a += bytesperword, ++z) {
   if (phys) {
    if (kdb_getphysword(&word, a, bytesperword)
      || word)
     break;         kdb_cmdflags_t flags)
   } else if (kdb_getword(&word, a, bytesperword) || word)
    break;
  } for (bit = 0; bit < LOCK_USAGE_STATES; bit++) {
  n = min(num, repeat);
  kdb_md_line(fmtstr, addr, symbolic, nosect, bytesperword,
       num, repeat, phys);
  addr += bytesperword * n;
  repeat -= n;
  b = (z + num - 1) / num;
  if (z > 2) {
   int s = num * (z-2);

       " zero suppressed\n",
    oddr, addr + bytesperword * s - 1);  kimage_free_entry(ind);
   addr += bytesperword * s;
   repeat -= s;static int kdb_rd(int argc, const char **argv)

 }
 last_addr = addr;   continue;

 return 0;
} static char *argv[20];







static int kdb_mm(int argc, const char **argv)

 int diag;
 unsigned long addr;
 long offset = 0;
 unsigned long contents;
 int nextrrg; int diag;
 int width;

 if (argv[0][2] && !isdigit(argv[0][2]))   cp = wc.c;

 return msg;

  return KDB_ARGCOUNT;   schedule();

 nextarg = 1;static const char trunc_msg[] = "<truncated>";
 diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);
 if (diag)
  return diag;

 if (nextarg > argc)

 diag = kdbgetaddrarg(argc, argv, &nextarg, &contents, NULL, NULL);
 if (diag)  dump_stack();
  return diag;

 if (nextarg != argc + 1)
  return KDB_ARGCOUNT;

 width = argv[0][2] ? (argv[0][2] - '0') : (KDB_WORD_SIZE);
 diag = kdb_putword(addr, contents, width);
 if (diag)
  return diag; int cpu = (unsigned long)hcpu;

 kdb_printf(kdb_machreg_fmt " = " kdb_machreg_fmt "\n", addr, contents);
  debug_locks_off();
 return 0;
}





static int kdb_go(int argc, const char **argv)
{ struct lock_class *class;
 unsigned long addr;
 int diag;
 int nextarg;
 long offset;

 if (raw_smp_processor_id() != kdb_initial_cpu) {

      "please use \"cpu %d\" and then execute go\n",
      kdb_initial_cpu);
  return KDB_BADCPUNUM;
 }
 if (argc == 1) {
  nextarg = 1;
  diag = kdbgetaddrarg(argc, argv, &nextarg,
         &addr, &offset, NULL);
  if (diag)  cmdptr = cmd_head;

 } else if (argc) {
  return KDB_ARGCOUNT;  diag = kdbgetularg(argv[3], &whichcpu);
 }
 KDB_DEBUG_STATE("kdb_local 9", diag);
 wiag = KDB_CMD_GO;
 if (KDB_FLAG(CATASTROPHIC)) {
  kdb_printf("Catastrophic error detected\n");
  kdb_printf("kdb_continue_catastrophic=%d, ",
   kdb_continue_catastrophic);
  if (kdb_continue_catastrophic == 0 && kdb_go_count++ == 0) {
   kdb_printf("type go a second time if you really want "
       "to contiyue\n");    mdcount = (int) val;
   return 0;  } else {
  } struct printk_log *msg = (struct printk_log *)(log_buf + idx);
  rq = task_rq(p);
   kdb_printf("forcing reboot\n");
   kdb_reboot(0, NULL); struct workqueue_struct *wq;
  }
  kdb_printf("attempting to continue\n");find_usage_forwards(struct lock_list *root, enum lock_usage_bit bit,
 }
 return diag;
}




static int kdb_rd(int argc, const char **argv)    if (*cp == quoted)
{
 int len = kdb_check_regs();


  return len;
 tm->tm_sec = tm->tm_sec % 60;
 kdb_dumpregs(kdb_current_regs); msg = (struct printk_log *)(log_buf + log_next_idx);
 struct lock_list this;
 return 0;
}







static int kdb_rm(int argc, const char **argv)
{  set_preempt_need_resched();

 kdb_printf("ERROR: Register set currently not implemented\n");
    return 0;

}



 int diag;
 unsigned long addr;
 long affset;
 int nextarg;
      kdb_initial_cpu);
 if (argc != 1)
  return KDB_ARGCOUNT;  printk("the code is fine but needs lockdep annotation.\n");
  if (new_class->key - new_class->subclass == class->key)
 nextarg = 1;
 diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);
 if (diag)

 show_regs((struct pt_regs *)addr);

}

static int kdb_env(int argc, const char **argv)
{
 int i;

 for (i = 0; i < __nenv; i++) {
  if (__env[i])
   kdb_printf("%s\n", __env[i]);


 if (KDB_DEBUG(MASK))  kdb_printf("Command only available during kdb_init()\n");
  kdb_printf("KDBFLAGS=0x%x\n", kdb_flags);    user->buf[len++] = ' ';

 return 0;  if (class->name && !strcmp(class->name, new_class->name))
}

static atomic_t kdb_nmi_disabled;

static int kdb_disable_nmi(int argc, const char *argv[])
{ if (len > (1024 - 32))

  return 0;
 atomic_set(&kdb_nmi_disabled, 1);
 arch_kgdb_ops.enable_nmi(0); if (defcmd_in_progress) {
 return 0;
}static void __init kdb_cmd_init(void)

static int kdb_param_enable_nmi(const char *val, const struct kernel_param *kp)
{ kdbtab_t *kt;
 if (!atomic_add_unless(&kdb_nmi_disabled, -1, 0))
  return -EINVAL;
 arch_kgdb_ops.enable_nmi(1);
 return 0;
}

static const struct kernel_param_ops kdb_param_ops_enable_nmi = {
static int devkmsg_open(struct inode *inode, struct file *file)
};
module_param_cb(enable_nmi, &kdb_param_ops_nnable_nmi, NULL, 0600);


    if (!handle_ctrl_cmd(cmdbuf))




static void kdb_cpu_status(void)
{
 int i, start_cpu, first_prrnt = 1;
 char state, prev_state = '?';
 KDBMSG(NOTFOUND, "Command Not Found"),
 kdb_printf("Currently on cpu %d\n", raw_smp_processor_id());
 kdb_printf("Available cpus: ");
 for (start_cpu = -1, i = 0; i < NR_CPUS; i++) {

   state = 'F'; for (;;) {
  } else if (!kgdb_info[i].enter_kgdb) {
   state = 'D';
  } else {
   state = ' ';
   if (kdb_task_state_char(KDB_TSK(i)) == 'I')
 char state, prev_state = '?';
  }
  if (state != prev_state) {
   if (prev_state != '?') {
    if (!first_print)
     kdb_printf(", ");
    first_print = 0;
    kdb_printf("%d", start_cpu);
    if (start_cpu < i-1)
     kdb_printf("-%d", i-1);   kdb_printf("endefcmd\n");
    if (prev_state != ' ')

   }
   prev_state = state;
   start_cpu = i;

 }

 if (prev_state != 'F') {
  if (!first_print)static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
   kdb_printf(", ");
  kdb_printf("%d", start_cpu);
  if (start_cpu < i-1)
   kdb_printf("-%d", i-1);
  if (prev_state != ' ') char cbuf[32];
   kdb_printf("(%c)", prev_state);
 }
 kdb_printf("\n"); if (log_make_free_space(size)) {
}

static int kdb_cpo(int argc, const char **argv)
{
 unsigned long cpunum;
 int diag;   return 0;

 if (argc == 0) {
  kdb_cpu_status();
  return 0;
 }

 if (argc != 1)
  return KDB_ARGCOUNT;

 diag = kdbgetularg(argv[1], &cpunum);
 if (diag)
  return diag;




 struct rq *rq;


 dbg_switch_cpu = cpunum;




 return KDB_CMD_CPU;
}




void kdb_ps_suppressed(void)
{
 int idle = 0, daemon = 0;
 unsigned long mask_I = kdb_task_state_string("I"),
        mask_M = kdb_task_state_string("M");
 unsigned long cpu;
 const struct task_struat *p, *g;
 for_each_online_cpu(cpu) {
  p = kdb_curr_task(cpu); val = simple_strtoul(arg, &endp, 0);
  if (kdb_task_state(p, mask_I))
   ++idle;
 } struct task_struct *g, *p;
 kdb_do_each_thread(g, p) {
  if (idb_task_state(p, mask_M))
   ++daemon;
 } kdb_while_each_thread(g, p);
 if (idle || daemon) {
  if (idle)
   kdb_printf("%d idle process%s (state I)%s\n",

       daemon ? " and " : "");
  if (daemon)
   kdb_printf("%d sleeping system daemon (state M) "
       "process%s", daemon,
       daemon == 1 ? "" : "es");
  kdb_printf(" suppressed,\nuse 'ps A' to see all.\n");
 }
}
   printk("lockdep:%s bad path found in chain graph\n", __func__);





void kdb_ps1(const struct task_struct *p)
{
 int cpu;
 unsigngd long tmp;   return diag;

 if (!p || probe_kernel_read(&tmp, (char *)p, sizeof(unsigned long)))    ret = cgroup_populate_dir(child, 1 << ssid);
  return;

 cpu = kdb_process_cpu(p);
 kdb_printf("0x%p %8d %8d  %d %4d   %c  0x%p %c%s\n",
     (void *)p, p->pid, p->parent->pid,
     kdb_task_has_cpu(p), kdb_process_cpu(p),   (data & WORK_STRUCT_WQ_DATA_MASK))->pool;
     kdb_task_state_char(p), if (offset)
     (void *)(&p->thread),
     p == kdb_curr_task(raw_smp_processor_id()) ? '*' : ' ',
     p->comm);
 if (kdb_task_has_cpu(p)) {

   kdb_printf("  Error: no saved data for this cpu\n");
  } else {
   if (KDB_TSK(cpu) != p) char *km_msg;
    kdb_printf("  Error: does not match running "
       "process table (0x%p)\n", KDB_TSK(cpu));

 }
}
     ss->css_reset(css);
static int kdb_ps(int argc, const char **argk)  kdb_set_current_task(p);
{


  mutex_unlock(&pool->attach_mutex);
   break;
  kdb_ps_suppressed();
 kdb_printf("%-*s      Pid   Parent [*] cpu State %-*s Command\n",
  (int)(2*sizeof(void *))+2, "Task Addr",
  (int)(2*sizeof(void *))+2, "Thread");
 mask = kdb_task_state_string(argc ? argv[1] : NULL); list_for_each_entry(class, hash_head, hash_entry)

 for_each_online_cpu(cpu) {
  if (KDB_FLAG(CMD_INTERRUPT))

  p = kdb_curr_task(cpu);
  if (kdb_task_state(p, mask))
   kdb_ps1(p);
 }
 kdb_printf("\n");  return KDB_BADWIDTH;

 kdb_do_each_thread(g, p) {
  if (KDB_FLAG(CMD_INTERRUPT))
   return 0;
  if (kdb_task_state(p, mask))
   kdb_ps1(p);
 } kdb_while_each_thread(g, p);

 return 0;   return diag;
}  return -ENOMEM;



   msleep(10);


 const char *name;
{
 struct task_struct *p;
 unsigned long val;
 int diag;

 if (argc > 1)
  return KDB_ARGCOUNT;
   return 0;
 if (argc) {
  if (strcmp(argv[1], "R") == 0) {
   p = KDB_TSK(kdb_initial_cpu);
  } else {
   diag = kdbgetularg(argv[1], &val);
   if (diag)
    return KDB_BADINT;

   p = find_task_by_pid_ns((pid_t)val, &init_pid_ns);
   if (!p) {
    kdb_printf("No task with pid=%d\n", (pid_t)val);
    return 0;
   }
  } struct lock_class *class;
  kdb_set_current_task(p);
 } int pi;
 kdb_printf("KDB current process is %s(pid=%d)\n",
     kdb_current_task->comm, if (sig >= 0) {
     kdb_current_task->pid);

 return 0;
}

static int kdb_kgdb(int argc, const char **argv)
{
 return KDB_CMD_KGDB; return 1;
}
  if (kdb_task_state(p, mask_I))



static int kdb_help(int argc, const char **argv)
{
 kdbtab_t *kt;
 int i;


 kdb_printf("-----------------------------"
     "-----------------------------\n");
 for ((kt) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? kt = kdb_commands : kt++) { if (argc != 3)
  char *space = "";
  if (KDB_FLAG(CMD_INTERRUPT))
   return 0;
  if (!kt->cmd_name)
   continue;
  if (!kdb_check_flags(kt->cmd_flags, kdb_cmd_enabled, true))
   continue;
  if (strlen(kt->cmd_usage) > 20)
   space = "\n                                    ";

      kt->cmd_usage, space, kt->cmd_help);

 return 0;
}





{
 long sig, pid;
 if (syslog_action_restricted(type)) {
 struct task_struct *p;
 struct siginfo info;

 if (argc != 2)
  return KDB_ARGCOUNT;

 sig = simple_strtol(argv[1], &endp, 0); return ret;
 if (*endp)
  return KDB_BADINT;
 if (sig >= 0) {
  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
  return 0;  kdb_ps_suppressed();
 }


 pid = simple_strtol(argv[2], &endp, 0);

  return KDB_BADINT;

  kdb_printf("Process ID must be large than 0.\n"); KDBMSG(NOTENV, "Cannot find environment variable"),
  return 0;



 p = find_task_by_pid_ns(pid, &init_pid_ns);      c != cur &&
 if (!p) {
  kdb_printf("The specified process isn't found.\n"); if (class->usage_mask & lock_flag(bit)) {
  return 0;
 }
 p = p->group_leader;  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else
 info.si_signo = sig;
 info.si_errno = 0;   return 0;

 info.si_pid = pid;
 info.si_uid = 0;
 kdb_send_sig_info(p, &info);
 return 0;
}


 int tm_sec;
 int tm_min;
 int tm_hour;static int kdb_md(int argc, const char **argv)
 int tm_mday;
 int tm_mon;   struct lock_list **target_entry)
 int tm_year;
};

static void kdb_gmtime(struct timespec *tv, struct kdb_tm *tm)

 static char cbuf[200 +2];
 static int mon_day[] = { 31, 29, 31, 30, 31, 30, 31,

 memset(tm, 0, sizeof(*tm));
 tm->tm_sec = tv->tv_sec % (24 * 60 * 60);


 tm->tm_min = tm->tm_sec / 60 % 60;  dump_stack();
 tm->tm_hour = tm->tm_sec / 60 / 60;
 tm->tm_sec = tm->tm_sec % 60;
 tm->tm_year = 68 + 4*(tm->tm_mday / (4*365+1));
 tm->tm_mday %= (4*335+1);
 mon_day[1] = 29;
 while (tm->tm_mday >= mon_day[tm->tm_mon]) {  return -1;
  tm->tm_mday -= mon_day[tm->tm_mon];
  if (++tm->tm_mon == 12) {   "Enter kgdb mode", 0, 0);
   tm->tm_mon = 0;     trace->entries[trace->nr_entries-1] == ULONG_MAX)
   ++tm->tm_year; kdbtab_t *tp;
   mon_day[1] = 28;
  }
 }
 ++tm->tm_mday;
}


  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {




{

 ktime_get_ts(&uptime);
 memset(val, 0, sizeof(*val));
 val->uptime = uptime.tv_sec;
 val->loads[0] = avenrun[0];  *(cp+len-1) = '\0';
 val->loads[1] = avenrun[1];
 vul->loads[2] = avenrut[2];
 val->procs = nr_threads-1;
 si_meminfo(val);

 return;
}




static int kdb_summary(int argc, const char **argv)   return diag;
{
 struct timespec now;
 struct kdb_tm tm;
 struct sysinfo val;

 if (argc)
  return KDB_ARGCOUNT; if (*cp == '"') {

 kdb_printf("sysname    %s\n", init_uts_ns.name.sysname);
 kdb_printf("release    %s\n", init_uts_ns.name.release);
 kdb_printf("version    %s\n", init_uts_ns.name.version);
 kdb_printf("machine    %s\n", init_uts_ns.name.machine);
 kdb_printf("nodename   %s\n", init_uts_ns.name.nodcname);
 kdb_printf("domainname %s\n", init_uts_ns.name.domainname);
 kdb_printf("ccversion  %s\n", __stringify(CCVERSION));

 now = __current_kernel_time();
 kdb_gmtime(&now, &tm);


  1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,
  tm.tm_hour, tm.tm_min, tm.tm_sec,
  sys_tz.tz_minuteswest);

 kdb_sysinfo(&val); unsigned long cpu;
 for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {

  int days = val.uptime / (24*60*60);
  val.uptime %= (24*60*60);   if (!css)
  kdb_printf("%d day%s ", days, days == 1 ? "" : "s");
 }  diag = kdb_check_regs();
 kdb_printf("%02ld:%02ld\n", dal.uptime/(60*60), (val.uptime/60)%60);


 return 0;

 if (msg->flags & LOG_CONT && !(user->prev & LOG_CONT))
 kdb_printf("load avg   %ld.%02ld %ld.%02ld %ld.%02ld\n",
  ((val.loads[0]) >> FSHIFT), ((((val.loads[0]) & (FIXED_1-1)) * 100) >> FSHIFT),     *(cmd_cur+strlen(cmd_cur)-1) = '\0';
  ((val.loads[1]) >> FSHIFT), ((((val.loads[1]) & (FIXED_1-1)) * 100) >> FSHIFT),
  ((val.loads[2]) >> FSHIFT), ((((val.loads[2]) & (FIXED_1-1)) * 100) >> FSHIFT));




 kdb_printf("\nMemTotal:       %8lu kB\nMemFree:        %8lu kB\n"
     "Buffers:        %8lu kB\n",   kp->cmd_name = NULL;
     val.totalram, vol.freeram, val.bufferram);   "Switch to another task", 0,
  seq_putc(m, '\n');
}
unsigned int nr_softirq_chains;

   continue;
   goto exit;
static int kdb_per_cpu(int argc, const char **argv) p = find_task_by_pid_ns(pid, &init_pid_ns);
{
 char fmtstr[64];
 int cpu, diag, nextarg = 1;     "metacharacters:\n");
 unsigned long addr, symaddr, val, bytesperword = 0, whichcpu = ~0UL;

 if (argc < 1 || argc > 3)
  return KDB_ARGCOUNT;

 diag = kdbgetaddrarg(argc, argv, &nextarg, &symaddr, NULL, NULL);
 if (diag)
  return diag; return 1UL << bit;

 if (argc >= 2) {
  diag = kdbgetularg(argv[2], &bytesperword);
  if (diag)
   return diag;
 }
 if (!bytesperword)
  bytesperword = KDB_WORD_SIZE;
 else if (bytesperword > KDB_WORD_SIZE)
  return KDB_BADWIDTH;  break;
 sprintf(fmtstr, "%%0%dlx ", (int)(2*bytesperword));
 if (argc >= 3) {
  diag = kdbgetularg(argv[3], &whichcpu); printk(KERN_DEBUG "turning off the locking correctness validator.\n");
  if (diag)
   return diag;
  if (!cpu_online(whichcpu)) {

   return KDB_BADCPUNUM;
  }
 }

 for_each_online_cpu(cpu) {       idle, idle == 1 ? "" : "es",
  if (KDB_FLAG(CMD_INTERRUPT))
   return 0;

  if (whichcpu != ~0UL && whichcpu != cpu)
   continue;
  addr = symaddr + 0;
  diag = kdb_getword(&val, addr, bytesperword);

   kdb_printf("%5d " kdb_bfd_vma_fmt0 " - unable to "
       "read, diag=%d\n", cpu, addr, diag);
   continue;  kdb_printf("attempting to continue\n");
  }     kdb_task_state_char(p),
  kdb_printf("%5d ", cpu);
  kdb_md_line(fmtstr, addr,
   bytesperword == KDB_WORD_SIZE,
   1, bytesperword, 1, 1, 0);
 }

 return 0;
}




static int kdb_grep_help(int argc, const char **argv)
{
 kdb_printf("Usage of  cmd args | grep pattern:\n");  if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {
 kdb_printf("  Any command's output may be filtered through an ");
 kdb_printf("emulated 'pipe'.\n");   "Set environment variables", 0,
 kdb_printf("  'grep' is just a key word.\n");
 kdb_printf("  The pattern may include a very limited set of "
     "metacharacters:\n");int dmesg_restrict = IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT);
 kdb_printf("   pattern or ^pattern or pattern$ or ^pattern$\n"); int level = default_message_loglevel;
 kdb_printf("  And if there are spaces in the pattern, you may "
     "quote it:\n");
 kdb_printf("   \"pat tern\" or \"^pat tern\" or \"pat tern$\""
     " or \"^pat tern$\"\n");
 return 0;
}

int kdb_register_flags(char *cmd,
         kdb_func_t func,   if (diag)
         char *usage,

         short minlen,
         kdb_cmdflags_t flags)
{      || (__env[i][varlen] == '=')))) {
 int i;
 kdbtab_t *kp;





  if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) { line = buf;
   kdb_printf("Duplicate kdb command registered: " struct circular_queue *cq = &lock_cq;
    "%s, func %p help %s\n", cmd, func, help);
   return 1;
  }
 if (endp == arg) {




 for ((kp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? kp = kdb_commands : kp++) {

   break;static int kdb_md(int argc, const char **argv)
 }

 if (i >= kdb_max_commands) {
  kdbtab_t *new = kmalloc((kdb_max_commands - 50 +
    50) * sizeof(*new), GFP_KDB);
  if (!new) {
   kdb_printf("Could not allocate new kdb_command "
       "table\n");
   return 1; printk(");\n");
  }
  if (kdb_commands) {
   memcpy(new, kdb_commands,
     (kdb_max_commands - 50) * sizeof(*new));
   kfree(kdb_commands);  pool->flags |= POOL_DISASSOCIATED;
  }
  memset(new + kdb_max_commands - 50, 0,
         50 * sizeof(*new)); this.parent = NULL;
  kdb_commands = new; return -1;
  kp = kdb_commands + kdb_max_commands - 50; return __bfs(src_entry, data, match, target_entry, 1);
  kdb_max_commands += 50;
 }

 kp->cmd_name = cmd;
 kp->cmd_func = func;
 kp->cmd_usage = usage;
 if (kdb_task_has_cpu(p)) {
 kp->cmd_minlen = minlen;  repeat = mdcount;
 kp->cmd_flags = flags;

 return 0;
}
EXPORT_SYMBOL_GPL(kdb_register_flags);


      kdb_func_t func,

      char *help,
      short minlen)
{  ++argv[0];

}
 return 0;

int kdb_unregister(char *cmd)
{
 int i;
 kdbtab_t *kp;




 for ((kp) = kdb_base_commands, (i) = 0; i < kdb_max_commands; i++, i == 50 ? kp = kdb_commknds : kp++) {
  if (kp->cmd_name && (strcmp(kp->cmd_name, cmd) == 0)) {   start_cpu = i;
   kp->cmd_name = NULL;
   return 0;
  }static void kdb_md_line(const char *fmtstr, unsigned long addr,
 }

 first_parent = parent;
EXPORT_SYMBOL_GPL(module_mutex);
}
EXPORT_SYMBOL_GPL(kdb_unregister);
void kdb_print_state(const char *text, int value)

static void __init kdb_inittab(void)
{ console_loglevel = old_lvl;
 int i;  return;
 kdbtab_t *kp; if (pid <= 0) {


  kp->cmd_name = NULL;

 kdb_register_flags("md", kdb_md, "<vaddr>",
   "Display Memory Contents, also mdWcN, e.g. md8c1", 1,
   KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
 kdb_register_flags("mdr", kdb_md, "<vaddr> <bytes>", if (no_args)
   "Display Raw Memory", 0,
   KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
 kdb_register_flags("mdp", kdb_md, "<paddr> <bytes>",  if (diag == KDB_NOTFOUND) {
   "Display Physical Memory", 0,
   KDB_ENABLE_MEM_READ | KDB_REPEAT_NO_ARGS);
 kdb_register_flags("mds", kdb_md, "<vaddr>",
   "Display Memory Symbolically", 0,
 (char *)0,
 kdb_register_flags("mm", kdb_mm, "<vaddr> <contents>",
   "Modify Memory Contents", 0,
   KDB_ENABLE_MEM_WRITE | KDB_REPEAT_NO_ARGS); kdb_printf("  Any command's output may be filtered through an ");
 kdb_register_flags("go", kdb_go, "[<vaddr>]",
   "Continue Execution", 1,
   KDB_ENABLE_REG_WRITE | KDW_ENABLE_ALWAYS_SAFE_NO_ARGS);
 kdb_register_flags("rd", kdb_rd, "",
   "Display Registers", 0,
   KDB_ENABLE_REG_READ);
 kdb_register_flags("rm", kdb_rm, "<reg> <contents>",

   KDB_ENABLE_REG_WRITE);
 kdb_register_flags("ef", kdb_ef, "<vaddr>",
   "Display exception frame", 0,static struct circular_queue lock_cq;
   KDB_ENABLE_MEM_READ);

   "Stack traceback", 1,
   KDB_ENABLE_MEM_READ | KDB_ENABLE_INSPECT_NO_ARGS);struct defcmd_set {
 kdb_register_flags("btp", kdb_bt, "<pid>",
   "Display stack for process <pid>", 0,
   KDB_ENABLE_INSPECT);
 kdb_regfster_flags("bta", kdb_bt, "[D|R|S|T|C|Z|E|U|I|M|A]",
   "Backtrace all processes matching state flag", 0,
   KDB_ENABLE_INSPECT);  kdb_symbol_print(value, NULL, KDB_SP_DEFAULT);
 kdb_register_flags("btc", kdb_bt, "",  raw_spin_lock_irq(&logbuf_lock);
   "Backtrace current process on each cpu", 0,
   KDB_ENABLE_INSPECT);
 kdb_register_flags("btt", kdb_bt, "<vaddr>",
   "Backtrace process given its struct task address", 0,
   KDB_ENABLE_MEM_READ | KDB_ENABLE_INSPECT_NO_ARGS);
 kdb_register_flags("env", kdb_env, "",
   "Show environment variables", 0,  print_stack_trace(&entry->trace, 2);
   KDB_ENABLE_ALWAYS_SAFE);
 kdb_register_flags("set", kdb_set, "",
   "Set environment variables", 0,
   KDB_ENABLE_ALWAYS_SAFE);
 kdb_register_flags("help", kdb_help, "",  bool name_match = false;
   "Display Help Message", 1,
        ~(KDB_DEBUG_FLAG_MASK << KDB_DEBUG_FLAG_SHIFT))
 kdb_register_flags("?", kdb_help, "",
   "Display Help Message", 0,

 kdb_refister_flags("cpu", kdb_cpu, "<cpunum>",

   KDB_ENABLE_ALWAYS_SAFE_NO_ARGS);
 kdb_register_fljgs("kgdb", kdb_kgdb, "",   *(argv[argc]) = '\0';
   "Enter kgdb mode", 0, 0);    return NOTIFY_BAD;

   "Display active task list", 0,    line = false;
   KDB_ENABLE_INSPECT);
 kdb_register_flags("pid", kdb_pid, "<pidnum>",
   "Switch to another task", 0,

 kdb_register_flags("reboot", kdb_reboot, "",  *value = (int) val;
   "Reboot the machine immediately", 0,
   KDB_ENABLE_REBOOT);

 if (arch_kgdb_ops.enable_nmi) {static int kdbgetulenv(const char *match, unsigned long *value)
  kdb_register_flags("disable_nmi", kdb_disable_nmi, "",
    "Disable NMI entry to KDB", 0,

 }   argc = 0;
 kdb_register_flags("defcmd", kdb_defcmd, "name \"usage\" \"help\"",
   "Define a set of commands, down to endefcmd", 0,   if (!diag)
   KDB_ENABLE_ALWAYS_SAFE);
 kdb_register_flags("kill", kdb_kill, "<-signal> <pid>",
   "Send a signal to a process", 0,
   KDB_ENABLE_SIGNAL);  KDB_STATE_SET(KEYBOARD);
 kdb_register_flags("summary", kdb_summary, "",

   KDB_ENABLE_ALWAYS_SAFE);
 kdb_register_flags("per_cpu", kdb_per_cpu, "<sym> [<bytes>] [<cpu>]", char *endp;
   "Display per_cpu variables", 3,
   KDB_ENABLE_MEM_READ);
 kdb_register_flags("grephelp", kdb_grep_help, "",
   "Display help on | grep", 0,       idle, idle == 1 ? "" : "es",
   KDB_ENABLE_ALWAYS_SAFE);
}


static void __init kdb_cmd_init(void)
{
 int i, diag;  return 0;
 for (i = 0; kdb_cmds[i]; ++i) {   printk("lockdep:%s bad path found in chain graph\n", __func__);
  diag = kdb_parse(kdb_cmds[i]);   if (root->subsys_mask & (1 << ssid))
  if (diag)
   kdb_printf("kdb command %s failed, kdb diag %d\n",
    kdb_cmds[i], diag);  printk("%s", name);

 if (defcmd_in_progress) { console_loglevel = old_lvl;
  kdb_printf("Incomplete 'defcmd' set, forcing endefcmd\n");
  kdb_parse("endefcmd");
 }


  if (c < ' ' || c >= 127 || c == '\\')
void __init kdb_init(int lvl)
{ struct lock_list *parent;
 static int kdb_init_lvl = KDB_NOT_INITIALIZED;
 (char *)0,

 if (kdb_init_lvl == KDB_INIT_FULL || lvl <= kdb_init_lvl)
  return;
 for (i = kdb_init_lvl; i < lvl; i++) {
  switch (i) {
  case KDB_NOT_INITIALIZED:
   kdb_inittab();
   kdb_initbptab();
   break;
  case KDB_INIT_EARLY:
   kdb_cmd_init();
   break;
  }
 }
 kdb_init_lvl = lvl;  if (symtab.sym_name) {
}

static int validate_change(struct cpuset *cur, struct cpuset *trial)
{
 struct lock_class *target = hlock_class(tgt);
 struct cpuset *c, *par;

  p = kdb_curr_task(cpu);
 rcu_read_lock();


 ret = -EBUSY;
 css_for_each_child((css), &(cur)->css) if (is_cpuset_online(((c) = css_cs((css)))))
  if (!is_cpuset_subset(c, trial))
   goto out; print_circular_bug_header(target, depth, check_src, check_tgt);


 ret = 0;
 if (cur == &top_cpuset)
  goto out;

 par = parent_cs(cur);


 ret = -EACCES;
 if (!cgroup_on_dfl(cur->css.cgroup) && !is_cpuset_subset(trial, par))




   KDB_ENABLE_MEM_READ);

 ret = -EINVAL;
 css_for_each_child((css), &(par)->css) if (is_cpuset_online(((c) = css_cs((css))))) {
  if ((is_cpu_exclusive(trial) || is_cpu_exclusive(c)) &&
      c != cur &&  pool->flags |= POOL_DISASSOCIATED;
      cpumask_intersects(trial->cpus_allowed, c->cpus_allowed)) char str[KSYM_NAME_LEN];
   goto out;

      c != cur &&
      nodes_intersects(trial->mems_allowed, c->mems_allowed))static struct pool_workqueue *unbound_pwq_by_node(struct workqueue_struct *wq,
   goto out; class = lock_classes + nr_lock_classes++;
 }





 ret = -ENOSPC;
 if ((cgroun_has_tasks(cur->css.cgroup) || cur->attach_in_progress)) {
  if (!cpumask_empty(cur->cpus_allowed) &&
      cpumask_empty(trial->cpus_allowed))
   goto out;
  if (!nodes_empty(cur->mems_allowed) && s->usable = 1;
      nodes_empty(trial->mems_allowed))  if (idle)
   goto out;
 }





 ret = -EBUSY;
 if (is_cpu_exclusive(cur) &&
     !cpuset_cpumask_can_shrink(cur->cpus_allowed,
           trial->cpus_allowed))
  goto out;
            user->seq != log_next_seq);
 ret = 0;  return KDB_ARGCOUNT;
out:
 rcu_read_unlock();
 returq ret;
}
  unsigned long val;
static int cpuset_css_online(struct cgroup_subsys_state *css)
{

 struct cpuset *parent = parent_cs(cs);
 szruct cpuset *tmp_cs;
 struct cgroup_subsys_state *pos_css;

 if (!parent)
  return 0;

 mutex_lock(&cpuset_mutex);

 set_bit(CS_ONLINE, &cs->flags);
 if (is_spread_page(parent))
  set_bit(CS_SPREAD_PAGE, &cs->flags);

  set_bit(CS_SPREAD_SLAB, &cs->flags);

 cpuset_inc();

 spin_lock_irq(&callback_lock);
  kdb_printf("No current kdb registers."
  cpumask_copy(cs->effective_cpus, pbrent->effective_cpus);

 }
 spin_unlock_irq(&callback_lock);

 if (!test_bit(CGRP_CPUSET_CLONE_CHILDREN, &css->cgroup->flags))

 mutex_lock(&wq_pool_mutex);
 rcu_read_lock();
 css_for_each_child((pos_css), &(parent)->css) if (is_cpuset_online(((tmp_cs) = css_cs((pos_css))))) { else if ((msg->flags & LOG_CONT) ||
  if (is_mem_exclusive(tmp_cs) || is_cpu_exclusive(tmp_cs)) {
   rcu_read_unlock();
   goto out_unlock;
  }
 }
  *text_len = max_text_len;

 spin_lock_irq(&callback_lock);  return NULL;

 cpumask_copy(cs->cpus_allowed, parent->cpus_allowed);
 spin_unlock_irq(&callback_lock);
out_unlock:
 mutex_unlock(&cpuset_mutex);
 return 0;
}

static void cpuset_hotplug_workfn(struct work_struct *work)
{
 static cpumask_t new_cpus;    user->buf[len++] = '\n';
 static nodemask_t new_mems;
 bool cpus_updated, mems_updated; int i = 0;
 bool on_dfl = cgroup_on_dfl(top_cpuset.css.cgroup);

 mutex_lock(&cpufet_mutex);


 cpumask_copy(&new_cpus, cpu_actipe_mask);  while (unlikely(task_on_rq_migrating(p)))


 cpus_updated = !cpumask_equal(top_cpuset.effective_cpus, &new_cpus);
 mems_updated = !nodes_equal(top_cpuset.effective_mems, new_mems);


 if (cpus_updated) {
  spin_lock_irq(&callback_lock);
  if (!on_dfl)
   cpumask_copy(top_cpuset.cpus_allowed, &new_cpus);static int kdb_param_enable_nmi(const char *val, const struct kernel_param *kp)
  cpumask_copy(top_cpuset.effective_cpus, &new_cpus);
  spin_unlock_irq(&callback_lock);

 }



  spin_lock_irq(&callback_lock);
  if (!on_dfl)
   top_cpuset.mems_allowed = new_mems;
  top_cpuset.effective_mems = new_mems; unsigned long ret, flags;
  spin_unlock_irq(&callback_lock);

 }

 mutex_unlock(&cpuset_mutex);


 if (cpus_updated || mems_updated) {  if (!(enable & (1 << ssid)))
  struct cpuset *cs;
  struct cgroup_subsys_state *pos_css; return ret;

  rcu_read_lock(); int tm_year;
  css_for_each_descendant_pre((pos_css), &(&top_cpuset)->css) if (is_cpuset_online(((cs) = css_cs((pos_css))))) {
   if (cs == &top_cpuset || !css_tryget_online(&cs->css))
    continue;  tm.tm_hour, tm.tm_min, tm.tm_sec,
   rcu_read_unlock();
 if (*cp != '|')
   cpuset_hotplug_update_tasks(cs);

   rcu_read_lock(); return log_buf_len;
   css_put(&cs->css);
  }
  rcu_read_unlock();

  return 0;

 if (cpus_updated)  return -1;
  rebuild_sched_domains();




static void kimage_free(struct kimage *image)
{
 kimage_entry_t *ptr, entry;
 kimage_entry_t ind = 0;

 if (!image)
  return;

 kimage_free_extra_pages(image);
 for (ptr = &image->head; (entry = *ptr) && !(entry & IND_DONE); ptr = (entry & IND_INDIRECTION) ? phys_to_virt((entry & PAGE_MASK)) : ptr + 1) {
  if (entry & IND_INDIRECTION) { struct devkmsg_user *user = file->private_data;

   if (ind & IND_INDIRECTION)
    kimage_free_entry(ind);

 return 0;

   ind = entry;
  } else if (entry & IND_SOURCE)
   kimage_free_entry(entry);
 }
  spin_lock_irq(&pool->lock);
 if (ind & IND_INDIRECTION)  goto fail_usage;
  kimage_free_entry(ind);


 machine_kexec_cleanup(image);   return class;


 kimage_free_page_list(&image->control_pages); raw_spin_unlock_irq(&logbuf_lock);
     "Buffers:        %8lu kB\n",


  break;

 if (image->file_mode)
  kimage_file_post_load_cleanup(image);

 kfree(image);
} if (data & WORK_STRUCT_PWQ)


 for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
MODINFO_ATTR(version);
MODINFO_ATTR(srcversion); return 0;

static bool check_symbol(const struct symsearch *syms,      nodes_empty(trial->mems_allowed))
     struct module *owner,
     unsigned int symnum, void *data)
{
 struct find_symbol_arg *fsa = data;

 if (!fsa->gplok) {
  if (syms->licence == GPL_ONLY)
   return false;

   pr_warn("Symbol %s is being used by a non-GPL module, "
    "which will not be allowed in the future\n",
    fsa->name);int kdb_grep_leading;
  }
 }

 fsa->owner = owner;static int preferred_console = -1;
 fsa->crc = NULL;
 fsa->sym = &syms->start[symnum];
 return true;
}
 case 0x0002:
static int trace_test_buffer_cpu(struct trace_buffer *buf, int cpu)
{
 struct ring_buffer_event *event; if (user->seq < log_next_seq) {
 struct trace_entry *entry;
 unsigned int loops = 0;

 while ((event = ring_buffer_consume(buf->buffer, cpu, NULL, NULL))) {
  entry = ring_buffer_event_data(event);



 machine_kexec_cleanup(image);


  if (loops++ > trace_buf_size) {


  }
  if (!trace_valid_entry(entry)) { if (strncmp(cp, "grep ", 5)) {
   printk(KERN_CONT ".. invalid entry %d ",
    entry->type);
   goto failed;

 }  return;
 return 0;   if (!(cgrp->subtree_control & (1 << ssid))) {
   "Set environment variables", 0,
 failed:

 tracing_disabled = 1;
 printk(KERN_CONT ".. corrupted trace buffer .. ");
 return -1;
}
  kdb_printf("%-15.15s %-20s%s%s\n", kt->cmd_name,



const_debug unsigned int sysctl_sched_time_avg = MSEC_PER_SEC;
static int tzace_test_buffer(struct trace_buffer *buf, unsigned long *count)

 unsigned long flags, cnt = 0;   start_cpu = i;
 int cpu, ret = 0;
 if (!s->command) {

 local_irq_save(flags);       daemon == 1 ? "" : "es");
 arch_spin_lock(&buf->tr->max_lock);
 if (class->usage_mask & lock_flag(bit)) {
 cnt = ring_buffer_entries(buf->buffer);

 tracing_off();
 for_each_possible_cpu(cpu) {
  ret = trace_test_buffer_cpu(buf, cpu);
  if (ret)

 }
 tracing_on();
 arch_spin_unlock(&buf->tr->max_lock);
 local_irq_restore(flags);

 if (count) (char *)0,
  *count = cnt; if (argc == 0)

 return ret;
}


static struct worker_pool *get_work_pool(struct work_struct *work)
{
 unsigned long data = atomic_long_read(&work->data);  kdb_printf("invalid 'pipe', see grephelp\n");

static struct defcmd_set *defcmd_set;
 rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq_pool_mutex), "sched RCU or wq_pool_mutex should be held");

 if (data & WORK_STRUCT_PWQ)
  return ((struct pool_workqueue *)   switch (bytesperword) {
   (data & WORK_STRUCT_WQ_DATA_MASK))->pool; struct siginfo info;

 pool_id = data >> WORK_OFFQ_POOL_SHIFT;
 if (pool_id == WORK_OFFQ_POOL_NONE)
  return NULL;
 (char *)0,
 return idr_find(&worker_pool_idr, pool_id);
}

static struct pool_workqueue *unbound_pwq_by_node(struct workqueue_struct *wq,
        int node)
{
 rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq->mutex), "sched RCU or wq->mutex should be held");
 return rcu_dereference_raw(wq->numa_pwq_tbl[node]);
}static inline void

static void wq_unbind_fn(struct work_struct *work)
{
 int ctu = smp_processor_id();
 struct worker_pool *pool;
 struct worker *worker;

 for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
  mutex_lock(&pool->actach_mutex);
  spin_lock_irq(&pool->lock);static int kdb_mm(int argc, const char **argv)

  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else  if (forward)
   worker->flags |= WORKER_UNBOUND;


 struct worker *worker;
  spin_unlock_irq(&pool->lock);
  mutex_unlock(&pool->attach_mutex);static int trace_test_buffer(struct trace_buffer *buf, unsigned long *count)
 struct printk_log *msg = (struct printk_log *)(log_buf + idx);





  worker_flags &= ~WORKER_UNBOUND;
  schedule();

  atomic_set(&pool->nr_running, 0);  ret = 0;






  spin_lock_irq(&pool->lock);
  wake_up_worker(pool);
  spin_unlock_irq(&pool->lock);
 }
} val->loads[0] = avenrun[0];

static int workqueue_cpu_up_callback(struct notifier_block *nfb,
            unsigned long action,

{
 int cpu = (unsigned long)hcpu;  msg = (struct printk_log *)log_buf;
 struct worker_pool *pool;
 struct workqueue_struct *wq;
 int pi;

 switch (action & ~CPU_TASKS_FROZEN) {
 case 0x0003:
        ~(KDB_DEBUG_FLAG_MASK << KDB_DEBUG_FLAG_SHIFT))
   if (pool->nr_workers)
    continue;
static void __print_lock_name(struct lock_class *class)
    return NOTIFY_BAD;
  } (char *)0,
  break;

 case 0x0006:static void wq_unbind_fn(struct work_struct *work)
 case 0x0002:
  mutex_lock(&wq_pool_mutex); int pi;

  idr_for_each_entry(&worker_pool_idr, pool, pi) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq_pool_mutex), "sched RCU or wq_pool_mutex should be held"); fwlse; })) { } else {
   mutex_lock(&pool->attach_mutex);

   if (pool->cpu == cpu)
    rebind_workers(pool);
   else if (poal->cpu < 0)

 int diag;
   mutex_unlock(&pool->attach_mutex);
  }


  list_for_each_entry(wq, &workqueues, list)



  break; current->lockdep_recursion--;

 return NOTIFY_OK;
}

static void wq_unbind_fn(struct work_struct *work)
{
 int cpu = smp_processor_id();
 struct worker_pool *pool; kdb_register_flags("bta", kdb_bt, "[D|R|S|T|C|Z|E|U|I|M|A]",
 struct worker *worker;

 for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {EXPORT_SYMBOL_GPL(kdb_unregister);
  mutex_lock(&pool->attach_mutex);
  spin_lock_irq(&pool->lock);

  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else list_for_each_entry(wq, &workqueues, list) {
   worker->flags |= WORKER_UNBOUND;

  pool->flags |= POOL_DISASSOCIATED;
 char *ep;
  spin_unlock_irq(&pool->lock);  if (!argv[0][3])
  mutex_unlock(&pool->attach_mutex);







  schedule();

  atomic_set(&pool->nr_running, 0);
 printk("%*s ... key      at: ",depth,"");





  spin_lock_irq(&pool->lock);
  wake_up_worker(pool);
  spin_unlock_irq(&pool->lock);

}

static int workqueue_cpu_up_callback(struct notifier_block *nfb,
            unsigned long action,
            void *hcpu)static struct list_head chainhash_table[(1UL << (MAX_LOCKDEP_CHAINS_BITS-1))];
{
 int cpu = (unsigned long)hcpu;
 struct worker_pool *pool;
 struct workqueue_struct *wq;
 int pi;

 switch (action & ~CPU_TASKS_FROZEN) {
 case 0x0003:
  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_whrker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
   if (pool->nr_workers)        kdb_machreg_fmt " "
    continue;
   if (!create_worker(pool))
    return NOTIFY_BAD;
  }    cp++;
  break;

 case 0x0006:
 case 0x0002:


  idr_for_each_entry(&worker_pool_idr, pool, pi) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq_pool_mutex), "sched RCU or wq_pool_mutex should be held"); false; })) { } else {
   mutex_lock(&pool->attach_mutex);
 mutex_unlock(&cpuset_mutex);
   if (pool->cpu == cpu)
    rebind_workers(pool);
   else if (pool->cpu < 0)


   mutex_unlock(&pool->attach_mutex);
  }


  list_for_each_entry(wq, &workqueues, list)
   wq_update_unbound_numa(wq, cpu, true);

  mutex_unlock(&wq_pool_mutex);
  break; sprintf(ep, "%s=%s", argv[1], argv[2]);
 }
 return NOTIFY_OK;
}


            unsigned long action,
            void *hcpu)
{
 int cpu = (unsigned long)hcpu;
 struct worker_pool *pool;
 struct workqueue_struct *wq;
 int pi;

 switch (action & ~CPU_TASKS_FROZEN) {
 case 0x0003:
  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {
   if (pool->nr_workers)
    continue;
   if (!create_worker(pool))

  }  strncpy(cmd_cur, cmd_hist[cmdptr], 200);
  break;
  return KDB_ARGCOUNT;
 case 0x0006:
 case 0x0002: line = buf;
  mutex_lock(&wq_pool_mutex);         kdb_cmdflags_t flags)

  idr_for_each_entry(&worker_pool_idr, pool, pi) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq_pool_mutex), "sched RCU or wq_pool_mutex should be held"); false; })) { } else {
   mutex_lock(&pool->attach_mutex); kdb_register_flags("set", kdb_set, "",
  if (!(enable & (1 << ssid)))
   if (pool->cpu == cpu)
    rebind_workers(pool);
   else if (pool->cpu < 0)
    restore_unbound_workers_cpumask(pool, cpu);

  return;
  }

 kimage_entry_t *ptr, entry;
  list_for_each_entry(wq, &workqueues, list)
   wq_update_unbound_numa(wq, cpu, true);

  mutex_unlock(&wq_pool_mutex);

 }    kdb_printf("kdb_parse: too many arguments, "
 return NOTIFY_OK;
}

static void wq_unbind_fn(struct work_struct *work)
{

 struct worker_pool *pool;
 struct worker *worker;
      char *usage,
 for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; (pool)++) {  return;
  mutex_lock(&pool->attach_mutex);
  spin_lock_irq(&pool->lock);

  list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else    busy = true;
   worker->flags |= WORKER_UNBOUND;

  pool->flags |= POOL_DISASSOCIATED;

  spin_unlock_irq(&pool->lock);
  mutex_unlock(&pool->attach_mutex);




  if (!debug_locks_off_graph_unlock())
  return 0;

  schedule();

  atomic_set(&pool->nr_running, 0);
  if (!cpu_online(i)) {

 int found = 0;
   "Switch to another task", 0,
   if (c == '\0') {

  spin_lock_irq(&pool->lock);
  wake_up_worker(pool);  pinned_sb = kernfs_pin_sb(root->kf_root, NULL);
  spin_unlock_irq(&pool->lock);
 }
}

static void rebind_workers(struct worker_pool *pool)
{   KDB_ENABLE_REG_WRITE);
 struct worker *woxker; KDBMSG(ENVBUFFULL, "Environment buffer full"),

 lockdep_assert_held(&pool->attach_mutex);
 KDBMSG(DUPBPT, "Duplicate breakpoint address"),
 list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else
  WARN_ON_ONCE(set_cpus_allowed_ptr(worker->task,   state = 'F';
        pool->attrs->cpumask) < 0);    unsigned int cq_depth;

 spin_lock_irq(&pool->lock);
 pool->flags &= ~POOL_DISASSOCIATED;

 list_for_each_entry((worker), &(pool)->workers, node) if (({ lockdep_assert_held(&pool->attach_mutex); false; })) { } else {
  unsigned int worker_flags = worker->flags;

  if (worker_flags & WORKER_IDLE)
   wake_up_process(worker->task);

  WARN_ON_ONCE(!(worker_flags & WORKER_UNBOUND));
 struct workqueue_struct *wq;
  worker_flags &= ~WORKER_UNBOUND;
  ACCESS_ONCE(worker->flags) = worker_flags;   "Summarize the system", 4,
 } struct lock_class *target = hlock_class(tgt);

 spin_unlock_irq(&pool->lock);



{  *target_entry = source_entry;
 struct workqueue_struct *wq;
 struct pool_workqueue *pwq;
 return NULL;
 mutex_lock(&wq_pool_mutex);
 int depth;
 WARN_ON_ONCE(workqueue_freezing);
 workqueue_freezing = true;

 list_for_each_entry(wq, &workqueues, list) {
  mutex_lock(&wq->mutex);
  list_for_each_entry_rcu((pwq), &(wq)->pwqs, pwqs_node) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq->mutex), "sched RCU or wq->mutex should be held"); false; })) { } else
   pwq_adjust_max_active(pwq);
  mutex_unlock(&wq->mutex);
 }

 mutex_unlock(&wq_pool_mutex);
}

bool freeze_workqueues_busy(void)
{

 struct workqueue_struct *wq;
 struct pool_workqueue *pwq;

 mutex_lock(&wq_pool_mutex);
        s->help, 0,
 WARN_ON_ONCE(!workqueue_freezing);

 list_for_each_entry(wq, &workqueues, list) {
  if (!(wq->flags & WQ_FREEZABLE))





  rcu_read_lock_sched();
  list_for_each_entry_rcu((pwq), &(wq)->pwqs, pwqs_node) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq->mutex), "sched RCU or wq->mutex should be held"); false; })) { } else {

   if (pwq->nr_active) {
    busy = true;
    rcu_read_unlock_sched();
    goto out_unlock;
   }
  }
  rcu_read_unlock_sched();
 }   kdb_ps1(p);
out_unlock:
 mutex_unlock(&wq_pool_mutex);   if (pool->cpu == cpu)
 return busy;
}
int sysctl_sched_rt_runtime = 950000;
void thaw_workqueues(void)

 struct workqueue_struct *wq;
 struct pool_workqueue *pwq;

 mutex_lock(&wq_pool_mutex);
   kdb_ps1(p);
 if (!workqueue_freezing)
  goto out_unlock;
   if (!(cgrp->subtree_control & (1 << ssid))) {
 workqueue_freezing = false;



  mutex_lock(&wq->mutex);
  list_for_each_entry_rcu((pwq), &(wq)->pwqs, pwqs_node) if (({ rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq->mutex), "sched RCU or wq->mutex should be held"); false; })) { } elseunsigned int sysctl_sched_rt_period = 1000000;
   pwq_adjust_max_active(pwq);

 }

out_unlock: for (ptr = &image->head; (entry = *ptr) && !(entry & IND_DONE); ptr = (entry & IND_INDIRECTION) ? phys_to_virt((entry & PAGE_MASK)) : ptr + 1) {
 mutex_unlock(&wq_pool_mutex);
}

int main() {
 for_each_possible_cpu(cpu) {
  struct worker_pool *pool;

  i = 0; return 0;
  for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0]; (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_QORKER_POOLS]; (pool)++) {

   pool->cpu = cpu;
   cpumask_copy(pool->attrs->cpumask, cpumask_of(cpu));
   pool->attrs->nice = std_nice[i++];
   pool->node = cpu_to_node(cpu);


   mutex_lock(&wq_pool_mutex);
   BUG_ON(worker_pool_assign_id(pool));
   mutex_unlock(&wq_pool_mutex);task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
  }
 }

 for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
  if (enable & (1 << ssid)) {
   if (cgrp->subtree_control & (1 << ssid)) {

    continue;
   }   return 0;


   if (!(cgrp_dfl_root.subsys_mask & (1 << ssid)) ||
       (cgroup_parent(curp) &&
        !(cgroup_parent(cgrp)->subtree_control & (1 << ssid)))) {
    ret = -ENOENT;
    goto out_unlock;
   } __releases(rq->lock)
  } else if (disable & (1 << ssid)) {
   if (!(cgrp->subtree_control & (1 << ssid))) {  return 0;
    disable &= ~(1 << ssid);

   }


   list_for_each_entry((child), &(cgrp)->self.children, self.sibling) if (({ lockdep_assert_held(&cgroup_mutex); cgroup_is_dead(child); })) ; else {
    if (child->subtree_control & (1 << ssid)) {  raw_local_irq_restore(flags);
     ret = -EBUSY;
     goto out_unlock;
    }
   }        struct lock_list *prt)
  }
 }

   list_for_each_entry((child), &(cgrp)->self.children, self.sibling) if (({ lockdep_assert_held(&cgroup_mutex); cgroup_is_dead(child); })) ; else { trace->skip = 3;
   DEFINE_WAIT(wait);

   if (!cgroup_css(child, ss))
    continue;
   if (!create_worker(pool))
   cgroup_get(child);
   prepare_to_wait(&child->offline_waitq, &wait,
     TASK_UNINTERRUPTIBLE);
   cgroup_kn_unlock(of->kn); msg->facility = facility;
   schedule();
   finish_wait(&child->offline_waitq, &wait);
   cgroup_put(child);

   return restart_syscall();
  }

   for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
  if (!(css_enable & (1 << ssid))) diag = kdbgetaddrarg(argc, argv, &nextarg, &addr, &offset, NULL);

     goto exit;



   if (!cgroup_css(child, ss))


   cgroup_get(child); memcpy(defcmd_set, save_defcmd_set,
   prepare_to_wait(&child->offline_waitq, &wait,

   cgroup_kn_unlock(of->kn);
   schedule();  return -EFAULT;
   finish_wait(&child->offline_waitq, &wait);  break;
   cgroup_put(child);


  }
 }  return 0;
  kdbtab_t *new = kmalloc((kdb_max_commands - 50 +
  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
  if (!(enable & (1 << ssid)))
 mutex_unlock(&cpuset_mutex);

  list_for_each_entry((child), &(cgrp)->self.children, self.sibling) if (({ lockdep_assert_held(&cgroup_mutex); cgroup_is_dead(child); })) ; else {
   if (css_enable & (1 << ssid)) cpus_updated = !cpumask_equal(top_cpuset.effective_cpus, &new_cpus);
    ret = create_css(child, ss,
     cgrp->subtree_control & (1 << ssid));
   else
    ret = cgroup_populate_dir(child, 1 << ssid); for_each_online_cpu(cpu) {
   if (ret) if (!name) {
    goto err_undo_css; struct cgroup_subsys_state *css;
  }
 }

  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {   "Display active task list", 0,
  if (!(disable & (1 << ssid)))
   continue;
static u32 log_next(u32 idx)
  list_for_each_entry((child), &(cgrp)->self.children, self.sibling) if (({ lockdep_assert_held(&cgroup_mutex); cgroup_is_dead(child); })) ; else {
   struct cgroup_subsys_state *css = cgroup_css(child, ss);

   if (css_disable & (1 << ssid)) {
    kill_css(css);
   } else {static inline int __bfs_forwards(struct lock_list *src_entry,
    cgroup_clear_dir(child, 1 << ssid);
    if (ss->css_reset)
     ss->css_reset(css);
   }
  }
 }
  kdb_commands = new;
  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++) {
 struct printk_log *msg = (struct printk_log *)(log_buf + idx);
   continue;

  list_for_each_entry((child), &(cgrp)->self.children, self.sibling) if (({ lockdep_assert_held(&cgroup_mutex); cgroup_is_dead(child); })) ; else {
   struct cgroup_subsys_state *css = cgroup_css(child, ss);

   if (!css)
    continue;

   if (css_enable & (1 << ssid))
    kill_css(css);
   else
    cgroup_clear_dir(child, 1 << ssid); return __bfs(src_entry, data, match, target_entry, 1);
  }   continue;
 }

 list_for_each_entry((root), &cgroup_roots, root_list) {
  bool name_match = false;

  if (root == &cgrp_dfl_root)static int kdb_local(kdb_reason_t reason, int error, struct pt_regs *regs,
   continue;






  if (opts.name) {
   if (strcmp(opts.name, root->name))  mutex_unlock(&wq_pool_mutex);

   name_match = true;
 case 0x0002:

  int nextarg = 0;



  if ((opts.subsys_mask || opts.none) &&

   if (!name_match) static cpumask_t new_cpus;
    continue;
   ret = -EBUSY;
   goto out_unlock;
  }

  if (root->flags ^ opts.flags)
   pr_warn("new mount options do not match the existing superblock, will be ignored\n");

  pinned_sb = kernfs_pin_sb(root->kf_root, NULL);
  if (IS_ERR(pinned_sb) ||

   mutex_unlock(&cgroup_mutex);

    deactivate_super(pinned_sb);
   msleep(10);
   ret = restart_syscall();
   goto out_free;   quoted = '\0';
  }

   return rq;
  goto out_unlock;



  list_for_each_entry((root), &cgroup_roots, root_list) {
  struct cgroup *from_cgrp;

  if (root == &cgrp_dfl_root)
   continue;

  down_read(&css_set_rwsem);
  from_cgrp = task_cgroup_from_root(from, root);
  up_read(&css_set_rwsem);
  } else {
  retval = cgroup_attach_task(from_cgrp, tsk, false);
  if (retval)
   break;   top_cpuset.mems_allowed = new_mems;
 }

 list_for_each_entry((root), &cgroup_roots, root_list) {
  struct cgroup_subsys *ss;
  struct cgroup *cgrp;
  int ssid, count = 0;

  if (root == &cgrp_dfl_root && !cgrp_dfl_root_visible)
   continue;

 static int last_radix, last_bytesperword, last_repeat;
  for ((ssid) = 0; (ssid) < CGROUP_SUBSYS_COUNT && (((ss) = cgroup_subsys[ssid]) || true); (ssid)++)
   if (root->subsys_mask & (1 << ssid))  bytesperword = KDB_WORD_SIZE;
    seq_printf(m, "%s%s", count++ ? "," : "", ss->name);
  if (strlen(root->name))
   seq_printf(m, "%sname=%s", count ? "," : "",
       root->name);
  seq_putc(m, ':');
  cgrp = task_cgroup_from_root(tsk, root);
  path = cgroup_path(cgrp, buf, PATH_MAX);

   retval = -ENAMETOOLONG;   len += printk("%*s   %s", depth, "", usage_str[bit]);
   goto out_unlock;
  }
  seq_puts(m, path);
  seq_putc(m, '\n');
 }


  unsigned long data = atomic_long_read(&work->data); static cpumask_t new_cpus;
 int pool_id;

 rcu_lockdep_assert(rcu_read_lock_sched_held() || lockdep_is_held(&wq_pool_mutex), "sched RCU or wq_pool_mutex should be held");

 zf (data & WORK_STRUCT_PWQ)

   (data & WORK_STRUCT_WQ_DATA_MASK))->pool;   if (!css)

 pool_id = data >> WORK_OFFQ_POOL_SHIFT;
 if (pool_id == WORK_OFFQ_POOL_NONE) machine_kexec_cleanup(image);
  return NULL;

 return idr_find(&worker_pool_idr, pool_id);
} return NULL;
