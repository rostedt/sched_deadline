#define _GNU_SOURCE
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <ctype.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <linux/unistd.h>
#include <linux/magic.h>

#ifdef __i386__
#ifndef __NR_sched_setattr
#define __NR_sched_setattr		351
#endif
#ifndef __NR_sched_getattr
#define __NR_sched_getattr		352
#endif
#ifndef __NR_getcpu
#define __NR_getcpu			309
#endif
#else /* x86_64 */
#ifndef __NR_sched_setattr
#define __NR_sched_setattr		314
#endif
#ifndef __NR_sched_getattr
#define __NR_sched_getattr		315
#endif
#ifndef __NR_getcpu
#define __NR_getcpu			309
#endif
#endif /* i386 or x86_64 */
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE		6
#endif

#define _STR(x) #x
#define STR(x) _STR(x)
#ifndef MAXPATH
#define MAXPATH 1024
#endif

#define CPUSET_ALL	"my_cpuset_all"
#define CPUSET_LOCAL	"my_cpuset"

#define gettid() syscall(__NR_gettid)
#define sched_setattr(pid, attr, flags) syscall(__NR_sched_setattr, pid, attr, flags)
#define sched_getattr(pid, attr, size, flags) syscall(__NR_sched_getattr, pid, attr, size, flags)
#define getcpu(cpup, nodep, unused) syscall(__NR_getcpu, cpup, nodep, unused)

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;

struct sched_attr {
	u32 size;

	u32 sched_policy;
	u64 sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	s32 sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	u32 sched_priority;

	/* SCHED_DEADLINE */
	u64 sched_runtime;
	u64 sched_deadline;
	u64 sched_period;
};

struct sched_data {
	u64 runtime_us;
	u64 deadline_us;
	u64 loop_time;

	u64 loops_per_period;

	u64 max_time;
	u64 min_time;
	u64 total_time;
	u64 nr_periods;

	int missed_periods;
	int missed_deadlines;
	u64 total_adjust;

	u64 last_deadline_missed;
	u64 last_time;

	int prio;
	int tid;

	int vol;
	int nonvol;
	int migrate;

	char buff[BUFSIZ+1];
};

static pthread_barrier_t barrier;

static int cpu_count;
static cpu_set_t *cpusetp;
static int cpuset_size;

static int nr_threads = 2;

static int mark_fd;

static int find_mount(const char *mount, char *debugfs)
{
	char type[100];
	FILE *fp;

	if ((fp = fopen("/proc/mounts","r")) == NULL)
		return 0;

	while (fscanf(fp, "%*s %"
		      STR(MAXPATH)
		      "s %99s %*s %*d %*d\n",
		      debugfs, type) == 2) {
		if (strcmp(type, mount) == 0)
			break;
	}
	fclose(fp);

	if (strcmp(type, mount) != 0)
		return 0;
	return 1;
}

static const char *find_debugfs(void)
{
	static int debugfs_found;
	static char debugfs[MAXPATH+1];

	if (debugfs_found)
		return debugfs;

	if (!find_mount("debugfs", debugfs))
		return "";
	
	debugfs_found = 1;

	return debugfs;
}

static int my_vsprintf(char *buf, int size, const char *fmt, va_list ap)
{
	const char *p;
	char tmp[100];
	char *s = buf;
	char *end = buf + size;
	char *str;
	long long lng;
	int l;
	int i;

	end[-1] = 0;

	for (p = fmt; *p && s < end; p++) {
		if (*p == '%') {
			l = 0;
 again:
			p++;
			switch (*p) {
			case 's':
				if (l) {
					fprintf(stderr, "Illegal print format l used with %%s\n");
					exit(-1);
				}
				str = va_arg(ap, char *);
				l = strlen(str);
				strncpy(s, str, end - s);
				s += l;
				break;
			case 'l':
				l++;
				goto again;
			case 'd':
				if (l == 1) {
					if (sizeof(long) == 8)
						l = 2;
				}
				if (l == 2)
					lng = va_arg(ap, long long);
				else if (l > 2) {
					fprintf(stderr, "Illegal print format l=%d\n", l);
					exit(-1);
				} else
					lng = va_arg(ap, int);
				i = 0;
				while (lng > 0) {
					tmp[i++] = (lng % 10) + '0';
					lng /= 10;
				}
				tmp[i] = 0;
				l = strlen(tmp);
				if (!l) {
					*s++ = '0';
				} else {
					while (l)
						*s++ = tmp[--l];
				}
				break;
			default:
				fprintf(stderr, "Illegal print format '%c'\n", *p);
				exit(-1);
			}
			continue;
		}
		*s++ = *p;
	}

	return s - buf;
}

#if 0
static int my_sprintf(char *buf, int size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return n;
}
#endif

static void ftrace_write(char *buf, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (mark_fd < 0)
		return;

	va_start(ap, fmt);
	n = my_vsprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);

	write(mark_fd, buf, n);
}

static void setup_ftrace_marker(void)
{
	struct stat st;
	const char *debugfs = find_debugfs();
	char files[strlen(debugfs) + 14];
	int ret;

	if (strlen(debugfs) == 0)
		return;

	sprintf(files, "%s/tracing/trace_marker", debugfs);
	ret = stat(files, &st);
	if (ret >= 0)
		goto found;
	/* Do nothing if not mounted */
	return;
found:
	mark_fd = open(files, O_WRONLY);
}

static int setup_hr_tick(void)
{
	const char *debugfs = find_debugfs();
	char files[strlen(debugfs) + strlen("/sched_features") + 1];
	char buf[500];
	struct stat st;
	static int set = 0;
	char *p;
	int ret;
	int len;
	int fd;

	if (set)
		return 1;

	set = 1;

	if (strlen(debugfs) == 0)
		return 0;

	sprintf(files, "%s/sched_features", debugfs);
	ret = stat(files, &st);
	if (ret < 0)
		return 0;

	fd = open(files, O_RDWR);
	perror(files);
	if (fd < 0)
		return 0;

	len = sizeof(buf);

	ret = read(fd, buf, len);
	if (ret < 0) {
		perror(files);
		close(fd);
		return 0;
	}
	if (ret >= len)
		ret = len - 1;
	buf[ret] = 0;

	ret = 1;

	p = strstr(buf, "HRTICK");
	if (p + 3 >= buf) {
		p -= 3;
		if (strncmp(p, "NO_HRTICK", 9) == 0) {
			ret = write(fd, "HRTICK", 6);
			if (ret != 6)
				ret = 0;
			else
				ret = 1;
		}
	}

	close(fd);
	return ret;
}

static int mounted(const char *path, long magic)
{
	struct statfs st_fs;

	if (statfs(path, &st_fs) < 0)
		return -1;
	if ((long)st_fs.f_type != magic)
		return 0;
	return 1;
}

#define CGROUP_PATH "/sys/fs/cgroup"
#define CPUSET_PATH CGROUP_PATH "/cpuset"

static int open_cpuset(const char *path, const char *name)
{
	char buf[MAXPATH];
	struct stat st;
	int ret;
	int fd;

	buf[MAXPATH - 1] = 0;
	snprintf(buf, MAXPATH - 1, "%s/%s", path, name);

	ret = stat(buf, &st);
	if (ret < 0)
		return ret;

	fd = open(buf, O_WRONLY);
	return fd;
}

static int mount_cpuset(void)
{
	struct stat st;
	int ret;
	int fd;

	/* Check if cgroups is already mounted. */
	ret = mounted(CGROUP_PATH, TMPFS_MAGIC);
	if (ret < 0)
		return ret;
	if (!ret) {
		ret = mount("cgroup_root", CGROUP_PATH, "tmpfs", 0, NULL);
		if (ret < 0)
			return ret;
	}
	ret = stat(CPUSET_PATH, &st);
	if (ret < 0) {
		ret = mkdir(CPUSET_PATH, 0755);
		if (ret < 0)
			return ret;
	}
	ret = mounted(CPUSET_PATH, CGROUP_SUPER_MAGIC);
	if (ret < 0)
		return ret;
	if (!ret) {
		ret = mount("cpuset", CPUSET_PATH, "cgroup", 0, "cpuset");
		if (ret < 0)
			return ret;
	}

	fd = open_cpuset(CPUSET_PATH, "cpuset.cpu_exclusive");
	if (fd < 0)
		return fd;
	ret = write(fd, "1", 2);
	close(fd);

	fd = open_cpuset(CPUSET_PATH, "cpuset.sched_load_balance");
	if (fd < 0)
		return fd;
	ret = write(fd, "0", 2);
	close(fd);

	return 0;
}

enum {
	CPUSET_FL_CPU_EXCLUSIVE		= (1 << 0),
	CPUSET_FL_MEM_EXCLUSIVE		= (1 << 1),
	CPUSET_FL_ALL_TASKS		= (1 << 2),
	CPUSET_FL_TASKS			= (1 << 3),
	CPUSET_FL_CLEAR_LOADBALANCE	= (1 << 4),
	CPUSET_FL_SET_LOADBALANCE	= (1 << 5),
	CPUSET_FL_CLONE_CHILDREN	= (1 << 6),
};

static const char *make_cpuset(const char *name, const char *cpus,
			       const char *mems, unsigned flags, ...)
{
	struct stat st;
	char path[MAXPATH];
	char buf[100];
	va_list ap;
	int ret;
	int fd;

	printf("Creating cpuset '%s'\n", name);
	snprintf(path, MAXPATH - 1, "%s/%s", CPUSET_PATH, name);
	path[MAXPATH - 1] = 0;

	ret = mount_cpuset();
	if (ret < 0)
		return "mount_cpuset";

	ret = stat(path, &st);
	if (ret < 0) {
		ret = mkdir(path, 0755);
		if (ret < 0)
			return "mkdir";
	}

	fd = open_cpuset(path, "cpuset.cpus");
	if (fd < 0)
		return "cset";
	ret = write(fd, cpus, strlen(cpus));
	close(fd);
	if (ret < 0)
		return "write cpus";

	if (mems) {
		fd = open_cpuset(path, "cpuset.mems");
		if (fd < 0)
			return "open mems";
		ret = write(fd, mems, strlen(mems));
		close(fd);
		if (ret < 0)
			return "write mems";
	}

	if (flags & CPUSET_FL_CPU_EXCLUSIVE) {
		fd = open_cpuset(path, "cpuset.cpu_exclusive");
		if (fd < 0)
			return "open cpu_exclusive";
		ret = write(fd, "1", 2);
		close(fd);
		if (ret < 0)
			return "write cpu_exclusive";
	}

	if (flags & (CPUSET_FL_CLEAR_LOADBALANCE | CPUSET_FL_SET_LOADBALANCE)) {
		fd = open_cpuset(path, "cpuset.sched_load_balance");
		if (fd < 0)
			return "open sched_load_balance";
		if (flags & CPUSET_FL_SET_LOADBALANCE)
			ret = write(fd, "1", 2);
		else
			ret = write(fd, "0", 2);
		close(fd);
		if (ret < 0)
			return "write sched_load_balance";
	}

	if (flags & CPUSET_FL_CLONE_CHILDREN) {
		fd = open_cpuset(path, "cgroup.clone_children");
		if (fd < 0)
			return "open clone_children";
		ret = write(fd, "1", 2);
		close(fd);
		if (ret < 0)
			return "write clone_children";
	}


	if (flags & CPUSET_FL_TASKS) {
		int *pids;
		int i;

		va_start(ap, flags);

		fd = open_cpuset(path, "tasks");
		if (fd < 0)
			return "open tasks";

		ret = 0;
		pids = va_arg(ap, int *);
		for (i = 0; pids[i]; i++) {
			sprintf(buf, "%d ", pids[i]);
			ret = write(fd, buf, strlen(buf));
		}
		va_end(ap);
		close(fd);
		if (ret < 0) {
			fprintf(stderr, "Failed on task %d\n", pids[i]);
			return "write tasks";
		}
	}

	if (flags & CPUSET_FL_ALL_TASKS) {
		FILE *fp;
		int pid;

		fd = open_cpuset(path, "tasks");

		snprintf(path, MAXPATH - 1, "%s/tasks", CPUSET_PATH);
		if ((fp = fopen(path,"r")) == NULL) {
			close (fd);
			return "opening cpuset tasks";
		}

		while (fscanf(fp, "%d", &pid) == 1) {
			sprintf(buf, "%d", pid);
			ret = write(fd, buf, strlen(buf));
			/*
			 * Tasks can come and go, the only error we care
			 * about is ENOSPC, as that means something went
			 * wrong that we did not expect.
			 */
			if (ret < 0 && errno == ENOSPC) {
				fclose(fp);
				close(fd);
				return "Can not move tasks";
			}
		}
		fclose(fp);
		close(fd);
	}

	return NULL;
}

static void destroy_cpuset(const char *name, int print)
{
	struct stat st;
	char path[MAXPATH];
	char buf[100];
	FILE *fp;
	int pid;
	int ret;
	int fd;
	int retry = 0;

	printf("Removing %s\n", name);
	snprintf(path, MAXPATH - 1, "%s/%s", CPUSET_PATH, name);
	path[MAXPATH - 1] = 0;

	ret = stat(path, &st);
	if (ret < 0)
		return;

 again:
	strncat(path, "/tasks", MAXPATH - 1);
	if ((fp = fopen(path,"r")) == NULL) {
		fprintf(stderr, "Failed opening %s\n", path);
		perror("fopen");
		return;
	}
	snprintf(path, MAXPATH - 1, "%s/tasks", CPUSET_PATH);
	path[MAXPATH - 1] = 0;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fclose(fp);
		fprintf(stderr, "Failed opening %s\n", path);
		perror("open");
		return;
	}

	while (fscanf(fp, "%d", &pid) == 1) {
		sprintf(buf, "%d", pid);
		if (print)
			printf("Moving %d out of %s\n", pid, name);
		write(fd, buf, strlen(buf));
	}
	fclose(fp);
	close(fd);

	snprintf(path, MAXPATH - 1, "%s/%s", CPUSET_PATH, name);
	path[MAXPATH - 1] = 0;

//	return;
	sleep(1);
	ret = rmdir(path);
	if (ret < 0) {
		if (retry++ < 5)
			goto again;
		fprintf(stderr, "Failed to remove %s\n", path);
		perror("rmdir");
		if (retry++ < 5) {
			fprintf(stderr, "Trying again\n");
			goto again;
		}
	}
}

static void teardown(void)
{
	int fd;

	fd = open_cpuset(CPUSET_PATH, "cpuset.cpu_exclusive");
	if (fd >= 0) {
		write(fd, "0", 2);
		close(fd);
	}

	fd = open_cpuset(CPUSET_PATH, "cpuset.sched_load_balance");
	if (fd >= 0) {
		write(fd, "1", 2);
		close(fd);
	}

	destroy_cpuset(CPUSET_ALL, 0);
	destroy_cpuset(CPUSET_LOCAL, 1);
}

static void bind_cpu(int cpu)
{
	int ret;

	printf("bind %d\n", cpu);
	CPU_ZERO_S(cpuset_size, cpusetp);
	CPU_SET_S(cpu, cpuset_size, cpusetp);

	ret = sched_setaffinity(0, cpuset_size, cpusetp);
	if (ret < 0)
		perror("sched_setaffinity bind");
}

static void unbind_cpu(void)
{
	int cpu;
	int ret;

	for (cpu = 0; cpu < cpu_count; cpu++)
		CPU_SET_S(cpu, cpuset_size, cpusetp);

	ret = sched_setaffinity(0, cpuset_size, cpusetp);
	if (ret < 0)
		perror("sched_setaffinity unbind");
}

static int set_thread_prio(pid_t pid, int prio)
{
	struct sched_param sp = { .sched_priority = prio };
	int policy = SCHED_FIFO;

	if (!prio)
		policy = SCHED_OTHER;

	/* set up our priority */
	return sched_setscheduler(pid, policy, &sp);
}

static int set_prio(int prio)
{
	return set_thread_prio(0, prio);
}

static void usage(char **argv)
{
	char *arg = argv[0];
	char *p = arg+strlen(arg);

	while (p >= arg && *p != '/')
		p--;
	p++;

	printf("usage: %s\n"
	       "\n",p);
	exit(-1);
}

static int done;
static int fail;

static u64 get_time_us(void)
{
	struct timespec ts;
	u64 time;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	time = ts.tv_sec * 1000000;
	time += ts.tv_nsec / 1000;

	return time;
}

static u64 run_loops(u64 loops)
{
	u64 start = get_time_us();
	u64 end;
	u64 i;
	int cpu;

	for (i = 0; i < loops; i++) {
		getcpu(&cpu, NULL, NULL);
		end = get_time_us();
	}

	return end - start;
}

static int get_value(const char *line)
{
	const char *p;

	for (p = line; isspace(*p); p++)
		;
	if (*p != ':')
		return -1;
	p++;
	for (; isspace(*p); p++)
		;
	return atoi(p);
}

static int update_value(const char *line, int *val, const char *name)
{
	int ret;

	if (strncmp(line, name, strlen(name)) == 0) {
		ret = get_value(line + strlen(name));
		if (ret < 0)
			return 0;
		*val = ret;
		return 1;
	}
	return 0;
}

static int read_ctx_switches(int *vol, int *nonvol, int *migrate)
{
	static int vol_once, nonvol_once;
	const char *vol_name = "nr_voluntary_switches";
	const char *nonvol_name = "nr_involuntary_switches";
	const char *migrate_name = "se.nr_migrations";
	char file[1024];
	char buf[1024];
	char *pbuf;
	int pid;
	size_t *pn;
	size_t n;
	FILE *fp;
	int r;

	pid = gettid();
	snprintf(file, 1024, "/proc/%d/sched", pid);
	fp = fopen(file, "r");
	if (!fp) {
		snprintf(file, 1024, "/proc/%d/status", pid);
		fp = fopen(file, "r");
		if (!fp) {
			fprintf(stderr, "could not open %s", file);
			return -1;
		}
		vol_name = "voluntary_ctxt_switches";
		nonvol_name = "nonvoluntary_ctxt_switches";
	}

	*vol = *nonvol = *migrate = -1;

	n = 1024;
	pn = &n;
	pbuf = buf;

	while ((r = getline(&pbuf, pn, fp)) >= 0) {

		if (update_value(buf, vol, vol_name))
			continue;

		if (update_value(buf, nonvol, nonvol_name))
			continue;

		if (update_value(buf, migrate, migrate_name))
			continue;
	}
	fclose(fp);

	if (!vol_once && *vol == -1) {
		vol_once++;
		fprintf(stderr, "Warning, could not find voluntary ctx switch count\n");
	}
	if (!nonvol_once && *nonvol == -1) {
		nonvol_once++;
		fprintf(stderr, "Warning, could not find nonvoluntary ctx switch count\n");
	}

	return 0;
}

static u64 do_runtime(long tid, struct sched_data *data, u64 period)
{
	u64 next_period = period + data->deadline_us;
	u64 now = get_time_us();
	u64 end;
	u64 diff;
	u64 time;

	if (now > next_period) {
		ftrace_write(data->buff,
			     "Missed a period start: %lld next: %lld now: %lld\n",
			     period, next_period, now);
		while (next_period < now) {
			next_period += data->deadline_us;
			data->missed_periods++;
		}
#if 0
		printf("[%ld] Missed a period last: %lld start: %lld\n", tid,
		       last_period_start, start);
#endif
	} else if (now < period) {
		u64 delta = period - now;
		/*
		 * The period could be off due to other deadline tasks
		 * preempting us when we started. If that's the case then
		 * adjust the current period.
		 */
		ftrace_write(data->buff,
			     "Adjusting period: now: %lld period: %lld delta:%lld%s\n",
			     now, period, delta, delta > data->deadline_us / 2 ?
			     " HUGE ADJUSTMENT" : "");
		data->total_adjust += delta;
		period = now;
		next_period = period + data->deadline_us;
	}

	ftrace_write(data->buff, "start at %lld off=%lld (period=%lld next=%lld)\n",
		     now, now - period, period, next_period);
	time = run_loops(data->loops_per_period);

	end = get_time_us();

	if (end > next_period) {
		ftrace_write(data->buff,
			     "Failed runtime by %lld\n",
			     end - next_period);
		data->missed_deadlines++;
		data->last_deadline_missed = end - next_period;
		/*
		 * We missed our deadline, which means we entered the
		 * next period. Move it forward one, if we moved it too
		 * much, then the next interation will adjust.
		 */
		next_period += data->deadline_us;
	}


	diff = end - now;
	if (diff > data->max_time)
		data->max_time = diff;
	if (!data->min_time || diff < data->min_time)
		data->min_time = diff;

	data->last_time = time;
	data->total_time += diff;
	data->nr_periods++;
	ftrace_write(data->buff,
		     "end at %lld diff: %lld run loops: %lld us\n", end, diff, time);

	return next_period;
}

void *run_deadline(void *data)
{
	struct sched_data *sched_data = data;
	struct sched_attr attr;
	int vol, nonvol, migrate;
	long tid = gettid();
	void *heap;
	u64 period;
	int ret;

	/*
	 * The internal glibc vsnprintf() used by ftrace_write()
	 * may alloc more space to do conversions. Alloc a bunch of
	 * memory and free it, and hopefully glibc doesn't return that
	 * back to the system (we did do an mlockall after all).
	 */
	heap = malloc(1000000);
	if (!heap) {
		perror("malloc");
		fail = 1;
		pthread_barrier_wait(&barrier);
		pthread_exit("Failed to alloc heap");
		return NULL;
	}
	free(heap);

	printf("deadline thread %ld\n", tid);

	sched_data->tid = tid;

	ret = sched_getattr(0, &attr, sizeof(attr), 0);
	if (ret < 0) {
		fprintf(stderr, "[%ld]", tid);
		perror("sched_getattr");
		fail = 1;
		pthread_barrier_wait(&barrier);
		pthread_exit("Failed sched_getattr");
		return NULL;
	}

	pthread_barrier_wait(&barrier);

	if (fail)
		return NULL;

	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = sched_data->runtime_us * 1000;
	attr.sched_deadline = sched_data->deadline_us * 1000;

	printf("thread[%ld] runtime=%lldus deadline=%lldus loops=%lld\n",
	       gettid(), sched_data->runtime_us,
	       sched_data->deadline_us, sched_data->loops_per_period);

	pthread_barrier_wait(&barrier);

	ret = sched_setattr(0, &attr, 0);
	if (ret < 0) {
		done = 0;
		fprintf(stderr, "[%ld]", tid);
		perror("sched_setattr");
		fail = 1;
		pthread_barrier_wait(&barrier);
		pthread_exit("Failed sched_setattr");
		return NULL;
	}

	pthread_barrier_wait(&barrier);

	if (fail)
		return NULL;

	sched_yield();
	period = get_time_us();
	
	while (!done) {
		period = do_runtime(tid, sched_data, period);
		sched_yield();
	}
	ret = sched_getattr(0, &attr, sizeof(attr), 0);
	if (ret < 0) {
		perror("sched_getattr");
		pthread_exit("Failed second sched_getattr");
	}

	read_ctx_switches(&vol, &nonvol, &migrate);

	sched_data->vol = vol;
	sched_data->nonvol = nonvol;
	sched_data->migrate = migrate;

	return NULL;
}

void *run_rt_spin(void *data)
{
	struct sched_data *sched_data = data;
	long tid = gettid();

	sched_data->tid = tid;

	if (set_prio(sched_data->prio) < 0) {
		fail = 1;
		pthread_barrier_wait(&barrier);
		pthread_exit("Failed setting prio");
		return NULL;
	}

	pthread_barrier_wait(&barrier);

	if (fail)
		return NULL;

	pthread_barrier_wait(&barrier);

	if (fail)
		return NULL;

	pthread_barrier_wait(&barrier);

	if (fail)
		return NULL;

	while (!done) {
		get_time_us();
	}

	return NULL;
}

struct cpu_list {
	struct cpu_list	*next;
	int		start_cpu;
	int		end_cpu;
};

static void add_cpus(struct cpu_list **cpu_list, int start_cpu, int end_cpu)
{
	struct cpu_list *list;

	while (*cpu_list && (*cpu_list)->end_cpu + 1 < start_cpu)
		cpu_list = &(*cpu_list)->next;

	if (!*cpu_list) {
		*cpu_list = malloc(sizeof(struct cpu_list));
		(*cpu_list)->start_cpu = start_cpu;
		(*cpu_list)->end_cpu = end_cpu;
		(*cpu_list)->next = NULL;
		return;
	}

	/* Look to concatinate */
	if (end_cpu > (*cpu_list)->start_cpu &&
	    start_cpu <= (*cpu_list)->end_cpu + 1) {
		if (start_cpu < (*cpu_list)->start_cpu)
			(*cpu_list)->start_cpu = start_cpu;
		list = (*cpu_list)->next;
		while (list && list->start_cpu <= end_cpu + 1) {
			(*cpu_list)->end_cpu = list->end_cpu;
			(*cpu_list)->next = list->next;
			free(list);
			list = (*cpu_list)->next;
		}
		if ((*cpu_list)->end_cpu < end_cpu)
			(*cpu_list)->end_cpu = end_cpu;
		return;
	}

	/* Check for overlaps */
	if (end_cpu >= (*cpu_list)->start_cpu - 1) {
		(*cpu_list)->start_cpu = start_cpu;
		return;
	}

	list = malloc(sizeof(struct cpu_list));
	list->start_cpu = start_cpu;
	list->end_cpu = end_cpu;
	list->next = (*cpu_list)->next;
	(*cpu_list)->next = list;
}

static int count_cpus(struct cpu_list *cpu_list)
{
	struct cpu_list *list;
	int cpus = 0;
	int fail = 0;

	while (cpu_list) {
		list = cpu_list;
		cpus += (list->end_cpu - list->start_cpu) + 1;
		if (list->end_cpu >= cpu_count)
			fail = 1;
		cpu_list = list->next;
		free(list);
	}
	return fail ? -1 : cpus;
}

static char *append_cpus(char *buf, int start, int end,
			 const char *comma, int *total)
{
	int len;

	if (start == end) {
		len = snprintf(NULL, 0, "%s%d", comma, start);
		buf = realloc(buf, *total + len + 1);
		buf[*total] = 0;
		snprintf(buf + *total, len + 1, "%s%d", comma, start);
	} else {
		len = snprintf(NULL, 0, "%s%d-%d", comma, start, end);
		buf = realloc(buf, *total + len + 1);
		buf[*total] = 0;
		snprintf(buf + *total, len + 1, "%s%d-%d", comma,
			 start, end);
	}
	*total += len;
	return buf;
}

static void make_new_list(struct cpu_list *cpu_list, char **buf)
{
	char *comma = "";
	int total = 0;

	while (cpu_list) {
		*buf = append_cpus(*buf, cpu_list->start_cpu, cpu_list->end_cpu,
				   comma, &total);
		comma = ",";
		cpu_list = cpu_list->next;
	}
}

static void make_other_cpu_list(const char *setcpu, char **cpus)
{
	const char *p = setcpu;
	const char *comma = "";
	int curr_cpu = 0;
	int cpu;
	int total = 0;

	while (*p && curr_cpu < cpu_count) {
		cpu = atoi(p);
		if (cpu > curr_cpu) {
			*cpus = append_cpus(*cpus, curr_cpu, cpu - 1,
					    comma, &total);
			comma = ",";
		}
		while (isdigit(*p))
			p++;
		if (*p == '-') {
			p++;
			cpu = atoi(p);
			while (isdigit(*p))
				p++;
		}
		curr_cpu = cpu + 1;
		if (*p)
			p++;
	}

	if (curr_cpu < cpu_count) {
		*cpus = append_cpus(*cpus, curr_cpu, cpu_count - 1,
				    comma, &total);
	}
}

static int calc_nr_cpus(const char *setcpu, char **buf)
{
	struct cpu_list *cpu_list = NULL;
	const char *p;
	int end_cpu;
	int cpu;

	for (p = setcpu; *p; ) {
		cpu = atoi(p);
		if (cpu < 0 || (!cpu && *p != '0'))
			goto err;

		while (isdigit(*p))
			p++;
		if (*p == '-') {
			p++;
			end_cpu = atoi(p);
			if (end_cpu < cpu || (!end_cpu && *p != '0'))
				goto err;
			while (isdigit(*p))
				p++;
		} else
			end_cpu = cpu;

		add_cpus(&cpu_list, cpu, end_cpu);
		if (*p == ',')
			p++;
	}

	make_new_list(cpu_list, buf);
	return count_cpus(cpu_list);
 err:
	/* Frees the list */
	count_cpus(cpu_list);
	return -1;
}

static const char *join_thread(pthread_t *thread)
{
	void *result;

	pthread_join(*thread, &result);
	return result;
}

static void sleep_to(u64 next)
{
	struct timespec req;
	u64 now = get_time_us();

	if (now > next)
		return;
	next -= now;
	req.tv_nsec = next * 1000;
	req.tv_sec = 0;
	while (req.tv_nsec > 1000000000UL) {
		req.tv_nsec -= 1000000000UL;
		req.tv_sec++;
	}
	nanosleep(&req, NULL);
}

static u64 calculate_loops_per_ms(u64 *overhead)
{
	struct sched_data sd = { };
	u64 loops;
	u64 diff;
	u64 odiff;
	u64 start;
	u64 end;

#define TEST_LOOPS 1000

	sleep_to(get_time_us() + 1000);

	sd.deadline_us = 2000;
	sd.runtime_us = 1000;
	sd.loops_per_period = TEST_LOOPS;

	start = get_time_us();
	do_runtime(0, &sd, start + sd.deadline_us);
	end = get_time_us();

	diff = end - start;

	/*
	 * diff / TEST_LOOPS = 1000us / loops
	 * loops = TEST_LOOPS * 1000us / diff
	 */

	loops = 1000 * TEST_LOOPS / diff;

	printf("loops=%lld diff=%lld for %d loops\n", loops, diff, TEST_LOOPS);

	sd.deadline_us = 2000;
	sd.runtime_us = 1000;
	sd.loops_per_period = loops;

	sleep_to(get_time_us() + 1000);

	start = get_time_us();
	do_runtime(0, &sd, start + sd.deadline_us);
	end = get_time_us();

	odiff = end - start;

	loops = TEST_LOOPS * 1000 / sd.last_time;

	*overhead = odiff - sd.last_time;

	printf("loops=%lld overhead=%lldus last_time=%lld diff=%lld\n",
	       loops, *overhead, sd.last_time, odiff - diff);


	return loops;
}

int main (int argc, char **argv)
{
	struct sched_data *sched_data;
	struct sched_data *sd;
	struct sched_data rt_sched_data;
	const char *res;
	const char *setcpu = NULL;
	char *setcpu_buf = NULL;
	char *allcpu_buf = NULL;
	pthread_t *thread;
	pthread_t rt_thread;
	unsigned int interval = 1000;
	unsigned int step = 500;
	u64 loops;
	u64 runtime;
	u64 overhead;
	u64 start_period;
	u64 end_period;
	int nr_cpus;
	int all_cpus = 0;
	int run_percent = 100;
	int percent = 80;
	int rt_task = 0;
	int i;
	int c;

	cpu_count = sysconf(_SC_NPROCESSORS_CONF);
	if (cpu_count < 1) {
		fprintf(stderr, "Can not calculate number of CPUS\n");
		exit(-1);
	}

	while ((c = getopt(argc, argv, "+hr:ac:p:P:t:")) >= 0) {
		switch (c) {
		case 'a':
			all_cpus = 1;
			break;
		case 'c':
			setcpu = optarg;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'p':
			percent = atoi(optarg);
			break;
		case 'P':
			run_percent = atoi(optarg);
			break;
		case 's':
			step = atoi(optarg);
			break;
		case 't':
			nr_threads = atoi(optarg);
			break;
		case 'r':
			rt_task = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv);
		}
	}

	if (rt_task < 0 || rt_task > 98) {
		fprintf(stderr, "RT task can only be from 1 to 98\n");
		exit(-1);
	}

	if (percent < 1 || percent > 100 || run_percent < 1 || run_percent > 100) {
		fprintf(stderr, "Percent must be between 1 and 100\n");
		exit(-1);
	}

	if (setcpu) {
		nr_cpus = calc_nr_cpus(setcpu, &setcpu_buf);
		if (nr_cpus < 0) {
			fprintf(stderr, "Invalid cpu input '%s'\n", setcpu);
			exit(-1);
		}
	} else
		nr_cpus = 1;

	if (!all_cpus && setcpu && cpu_count == nr_cpus) {
		printf("Using all CPUS\n");
		all_cpus = 1;
	}

	/* Default cpu to use is the last one */
	if (!all_cpus && !setcpu) {
		setcpu_buf = malloc(10);
		if (!setcpu_buf) {
			perror("malloc");
			exit(-1);
		}
		sprintf(setcpu_buf, "%d", cpu_count - 1);
	}

	setcpu = setcpu_buf;

	if (setcpu)
		make_other_cpu_list(setcpu, &allcpu_buf);

	/*
	 * Now the amount of bandwidth each tasks takes will be
	 * percent * nr_cpus / nr_threads. Now if nr_threads is
	 * But the amount of any one thread can not be more than
	 * 90 of the CPUs.
	 */
	percent = (percent * nr_cpus) / nr_threads;
	if (percent > 90)
		percent = 90;
	printf("percent = %d\n", percent);
	printf("nr_cpus=%d %s\n", nr_cpus, setcpu);

	if (mlockall(MCL_CURRENT|MCL_FUTURE) == -1) {
		perror("mlockall");
	}

	cpusetp = CPU_ALLOC(cpu_count);
	cpuset_size = CPU_ALLOC_SIZE(cpu_count);
	if (!cpusetp) {
		perror("allocating cpuset");
		exit(-1);
	}

	setup_ftrace_marker();

	thread = calloc(nr_threads, sizeof(*thread));
	sched_data = calloc(nr_threads, sizeof(*sched_data));
	if (!thread || !sched_data) {
		perror("allocating threads");
		exit(-1);
	}

	set_prio(99);

	bind_cpu(cpu_count - 1);

	loops = calculate_loops_per_ms(&overhead);

	printf("loops=%lld overhead=%lld\n", loops, overhead);

	/* Set up the data while sill in SCHED_FIFO */
	for (i = 0; i < nr_threads; i++) {
		sd = &sched_data[i];
		/*
		 * Interval is the deadline/period
		 * The runtime is the percentage of that period.
		 */
		runtime = interval * percent / 100;
		if (runtime < overhead) {
			fprintf(stderr, "Run time too short: %lld us\n",
				runtime);
			fprintf(stderr, "Read context takes %lld us\n",
				overhead);
			exit(-1);
		}
		if (runtime < 2000) {
			/*
			 * If the runtime is less than 2ms, then we better
			 * have HRTICK enabled.
			 */
			if (!setup_hr_tick()) {
				fprintf(stderr, "For less that 2ms run times, you need to\n"
					"have HRTICK enabled in debugfs/sched_features\n");
				exit(-1);
			}
		}
		sd->runtime_us = runtime;
		/* Account for the reading of context switches */
		runtime -= overhead;
		/*
		 * loops is # of loops per ms, convert to us and
		 * take 5% off of it.
		 *  loops * %run_percent / 1000
		 */
		sd->loop_time = runtime * run_percent / 100;
		sd->loops_per_period = sd->loop_time * loops / 1000;

		printf("loops per period = %lld\n", sd->loops_per_period);

		sd->deadline_us = interval;
		printf("interval: %lld:%lld\n", sd->runtime_us, sd->deadline_us);

		/* Make sure that we can make our deadlines */
		start_period = get_time_us();
		do_runtime(gettid(), sd, start_period);
		end_period = get_time_us();
		if (end_period - start_period > sd->runtime_us) {
			fprintf(stderr, "Failed to perform task within runtime: Missed by %lld us\n",
				end_period - start_period - sd->runtime_us);
			exit(-1);
		}

		printf("  Tested at %lldus of %lldus\n",
		       end_period - start_period, sd->runtime_us);

		interval += step;
	}

	set_prio(0);

	unbind_cpu();

	pthread_barrier_init(&barrier, NULL, nr_threads + 1 + !!rt_task);

	for (i = 0; i < nr_threads; i++) {
		sd = &sched_data[i];
		pthread_create(&thread[i], NULL, run_deadline, sd);
	}

	/* Make sure we are a higher priority than the spinner */
	set_prio(rt_task + 1);

	if (rt_task) {
		rt_sched_data.prio = rt_task;
		pthread_create(&rt_thread, NULL, run_rt_spin, &rt_sched_data);
	}

#if 0
	sd = &sched_data[0];
	sd->runtime_us = 20 * 1000;
	sd->deadline_us = 30 * 1000;
	sd->loops_per_period = (loops * 20 * 95)/100 - readctx * 2;
	pthread_create(&thread[0], NULL, run_deadline, sd);

	sd = &sched_data[1];
	sd->runtime_us = 20 * 1000;
	sd->deadline_us = 200 * 1000;
	sd->loops_per_period = (loops * 20 * 95)/100 - readctx * 2;
	pthread_create(&thread[1], NULL, run_deadline, sd);

#endif
	atexit(teardown);

	pthread_barrier_wait(&barrier);

	if (fail) {
		printf("fail 1\n");
		exit(-1);
	}

	if (!all_cpus) {
		int *pids;

		res = make_cpuset(CPUSET_ALL, allcpu_buf, "0",
//				  CPUSET_FL_CPU_EXCLUSIVE |
				  CPUSET_FL_SET_LOADBALANCE |
				  CPUSET_FL_CLONE_CHILDREN |
				  CPUSET_FL_ALL_TASKS);
		if (res) {
			perror(res);
			exit(-1);
		}

		pids = calloc(nr_threads + !!rt_task + 1, sizeof(int));
		if (!pids) {
			perror("Allocating pids");
			exit(-1);
		}

		for (i = 0; i < nr_threads; i++)
			pids[i] = sched_data[i].tid;
		if (rt_task)
			pids[i++] = rt_sched_data.tid;

		res = make_cpuset(CPUSET_LOCAL, setcpu, "0",
				  CPUSET_FL_CPU_EXCLUSIVE |
				  CPUSET_FL_SET_LOADBALANCE |
				  CPUSET_FL_CLONE_CHILDREN |
				  CPUSET_FL_TASKS, pids);
		free(pids);
		if (res) {
			perror(res);
			exit(-1);
		}

		system("cat /sys/fs/cgroup/cpuset/my_cpuset/tasks");
	}

	printf("main thread %ld\n", gettid());

	pthread_barrier_wait(&barrier);
	printf("fail 2 %d\n", fail);

	if (fail)
		exit(-1);

	pthread_barrier_wait(&barrier);

	if (!fail)
		sleep(10);
	printf("fail 3? %d \n", fail);

	done = 1;
	if (rt_task) {
		res = join_thread(&rt_thread);
		if (res)
			printf("RT Thread failed: %s\n", res);
	}

	for (i = 0; i < nr_threads; i++) {

		sd = &sched_data[i];

		res = join_thread(&thread[i]);
		if (res) {
			printf("Thread %d failed: %s\n", i, res);
			continue;
		}

		printf("\n[%d]\n", sd->tid);
		printf("deadline : %lld us\n", sd->deadline_us);
		printf("runtime  : %lld us\n", sd->runtime_us);
		printf("max_time  = %lld\n", sd->max_time);
		printf("min_time  = %lld\n", sd->min_time);
		printf("avg_time  = %lld\n", sd->total_time / sd->nr_periods);
		printf("nr_periods        = %lld\n", sd->nr_periods);
		printf("missed deadlines  = %d\n", sd->missed_deadlines);
		printf("missed periods    = %d\n", sd->missed_periods);
		printf("Total adjustments = %lld us\n", sd->total_adjust);
		printf("ctx switches vol:%d nonvol:%d migration:%d\n",
		       sd->vol, sd->nonvol, sd->migrate);
		printf("\n");
	}

	free(setcpu_buf);
	return 0;
}
