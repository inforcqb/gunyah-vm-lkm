// SPDX-License-Identifier: GPL-2.0
/*
 * ghvmprobe.c — Gunyah HLOS 侧 VM 生命周期探针（/proc 交互式，只读优先）
 *
 * 用法：
 *   insmod ghvmprobe.ko            # 只注册 /proc/ghvmprobe，什么都不做
 *   echo help   > /proc/ghvmprobe  # 命令；结果留在缓冲里
 *   cat /proc/ghvmprobe            # 读回结果
 *
 * 背景（2026-10-11 静态 + 设备实测）：
 *   - RM(EL2) 对 caller vmid==3(HLOS) 开放 VM 生命周期服务：VM_ALLOC_VMID(0x56000001)、
 *     VM_CONFIG_IMAGE(0x56000009)、VM_AUTH_IMAGE、VM_INIT(0x5600000b)、VM_START(0x56000004)。
 *   - vmid 分配池在 RM 初始化里硬编码为 {45,49,50}（rm2.elf @0x35ae0/0x35ae4）。
 *   - VM_CONFIG_IMAGE 报文的 auth_mech 由请求方填（payload[+2]），0 = 免认证分支。
 *   - 状态机：5=LOAD →(CONFIG_IMAGE) 6=AUTH →(INIT) 1 → 2=READY →(START) 3=RUNNING。
 *
 * 驱动侧名字表（gh_rm_core.c:71-81；vmid 与枚举无关，RM 只看报文里的 vmid）：
 *   enum { GH_SELF_VM=0, GH_PRIMARY_VM=1, GH_TRUSTED_VM=2, GH_CPUSYS_VM=3,
 *          GH_OEM_VM=4, GH_AUTO_VM=5, GH_VM_MAX=6 };
 *   gh_get_image_name(str) 比 image_name；gh_get_vm_name(str) 比 vm_name；未命中返回 6。
 *   gh_rm_get_vmid(enum,&vmid)：本地表查询，表项 vmid==0 返回 -EINVAL(-22)，
 *   未分配的表项是 GH_VMID_INVAL(0xffff)。
 *
 * 未定义符号直接声明，由 ksud insmod 在用户态按名填地址（SHN_UNDEF → SHN_ABS）。
 * 这些都是**直接调用**（编译期已知符号），不走 CFI 间接调用检查，无需 __nocfi。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/stdarg.h>

#define DRV_TAG "ghvmprobe: "
#define PROBE_NAME "ghvmprobe"
#define OUT_SZ 8192

typedef u16 gh_vmid_t;
#define GH_VMID_INVAL 0xffff
#define GH_VM_MAX_ENUM 6

/* ---- 直接声明：类型必须与 vendor 驱动一致 ---- */
extern int gh_get_image_name(const char *str);	/* enum gh_vm_names */
extern int gh_get_vm_name(const char *str);	/* enum gh_vm_names */
extern int gh_rm_get_vmid(int vm_name, gh_vmid_t *vmid);
extern int gh_rm_get_vm_name(gh_vmid_t vmid, int *vm_name);
extern int gh_rm_get_vm_id_info(gh_vmid_t vmid);
extern int gh_rm_vm_alloc_vmid(int vm_name, int *vmid);
extern int gh_rm_vm_dealloc_vmid(gh_vmid_t vmid);

static const char *const image_names[] = {
	"pvm", "trustedvm", "cpusys_vm", "oem_vm", "autoghgvm",
};
static const char *const vm_names[] = {
	"", "qcom,trustedvm", "qcom,cpusysvm", "qcom,oemvm", "qcom,autoghgvm",
};
static const char *const enum_names[] = {
	"GH_SELF_VM", "GH_PRIMARY_VM", "GH_TRUSTED_VM",
	"GH_CPUSYS_VM", "GH_OEM_VM", "GH_AUTO_VM",
};

static DEFINE_MUTEX(gh_lock);
static char gh_buf[OUT_SZ];
static size_t gh_len;

static void out(const char *fmt, ...)
{
	va_list ap;
	int n;

	if (gh_len >= OUT_SZ - 1)
		return;
	va_start(ap, fmt);
	n = vsnprintf(gh_buf + gh_len, OUT_SZ - gh_len, fmt, ap);
	va_end(ap);
	if (n > 0)
		gh_len += (size_t)n;
	if (gh_len > OUT_SZ - 1)
		gh_len = OUT_SZ - 1;
	gh_buf[gh_len] = '\0';
}

static int probe_vmid(int nm, gh_vmid_t *v)
{
	int ret;

	*v = GH_VMID_INVAL;
	ret = gh_rm_get_vmid(nm, v);
	return ret;
}

static int first_free_enum(void)
{
	int i;

	for (i = 1; i < GH_VM_MAX_ENUM; i++) {
		gh_vmid_t v;
		int ret = probe_vmid(i, &v);

		if (!ret && v == GH_VMID_INVAL)
			return i;
	}
	return -1;
}

/* ---------------- 命令实现 ---------------- */

static void cmd_help(void)
{
	out("commands:\n");
	out("  help              this text\n");
	out("  names             name maps + per-enum vmid occupancy (read-only)\n");
	out("  rev <vmid>        vmid -> enum (read-only)\n");
	out("  idinfo <vmid>     gh_rm_get_vm_id_info(vmid)  (RM RPC, read-only)\n");
	out("  alloc [enum]      gh_rm_vm_alloc_vmid(enum, vmid=0); enum default = first free\n");
	out("  dealloc <vmid>    gh_rm_vm_dealloc_vmid(vmid)\n");
	out("  clear             clear this buffer\n");
	out("(later stages: lend / config / auth / init / start)\n");
}

static void cmd_names(void)
{
	int i;

	out("-- name maps (gh_rm_core.c vm_name_map[]) --\n");
	for (i = 0; i < ARRAY_SIZE(image_names); i++)
		out("  image '%s' -> %d ; vm_name '%s' -> %d\n",
		    image_names[i], gh_get_image_name(image_names[i]),
		    vm_names[i], gh_get_vm_name(vm_names[i]));

	out("-- per-enum vmid (gh_rm_get_vmid, local table) --\n");
	for (i = 0; i < GH_VM_MAX_ENUM; i++) {
		gh_vmid_t v;
		int ret = probe_vmid(i, &v);

		out("  %-14s enum %d : ret=%d vmid=%u%s\n", enum_names[i], i, ret,
		    (unsigned)v, (v == GH_VMID_INVAL) ? "  free" : "  IN USE");
	}
}

static void cmd_rev(int vmid)
{
	int nm = GH_VM_MAX_ENUM;
	int ret = gh_rm_get_vm_name((gh_vmid_t)vmid, &nm);

	out("gh_rm_get_vm_name(%d) -> ret=%d enum=%d%s\n", vmid, ret, nm,
	    (nm >= 0 && nm < GH_VM_MAX_ENUM) ? enum_names[nm] : "");
}

static void cmd_idinfo(int vmid)
{
	int ret = gh_rm_get_vm_id_info((gh_vmid_t)vmid);

	out("gh_rm_get_vm_id_info(%d) -> ret=%d\n", vmid, ret);
}

static void cmd_alloc(int arg_enum, int has_arg)
{
	int i = has_arg ? arg_enum : first_free_enum();
	int vmid = 0;
	int ret;

	if (i < 0) {
		out("alloc: no free enum slot\n");
		return;
	}
	if (i <= 0 || i >= GH_VM_MAX_ENUM) {
		out("alloc: enum %d out of range (1..%d)\n", i, GH_VM_MAX_ENUM - 1);
		return;
	}
	out("alloc: using enum %d (%s), requesting vmid=0 (RM picks)\n",
	    i, enum_names[i]);
	ret = gh_rm_vm_alloc_vmid(i, &vmid);
	out("gh_rm_vm_alloc_vmid(%d) -> ret=%d vmid=%d\n", i, ret, vmid);
}

static void cmd_dealloc(int vmid)
{
	int ret = gh_rm_vm_dealloc_vmid((gh_vmid_t)vmid);

	out("gh_rm_vm_dealloc_vmid(%d) -> ret=%d\n", vmid, ret);
}

/* ---------------- 解析 ---------------- */

static int simple_atoi(const char *s)
{
	int v = 0, neg = 0;

	while (*s == ' ')
		s++;
	if (*s == '-') {
		neg = 1;
		s++;
	}
	while (*s >= '0' && *s <= '9')
		v = v * 10 + (*s++ - '0');
	return neg ? -v : v;
}

static int has_prefix(const char *s, const char *p)
{
	while (*p)
		if (*s++ != *p++)
			return 0;
	return 1;
}

static void dispatch(const char *cmd)
{
	const char *p = cmd;

	out("$ %s\n", cmd);
	if (has_prefix(p, "help")) {
		cmd_help();
	} else if (has_prefix(p, "clear")) {
		gh_len = 0;
		gh_buf[0] = '\0';
	} else if (has_prefix(p, "names")) {
		cmd_names();
	} else if (has_prefix(p, "rev")) {
		p += 3;
		cmd_rev(simple_atoi(p));
	} else if (has_prefix(p, "idinfo")) {
		p += 6;
		cmd_idinfo(simple_atoi(p));
	} else if (has_prefix(p, "dealloc")) {
		p += 7;
		cmd_dealloc(simple_atoi(p));
	} else if (has_prefix(p, "alloc")) {
		p += 5;
		while (*p == ' ')
			p++;
		cmd_alloc(simple_atoi(p), *p != '\0');
	} else {
		out("unknown command: %s\n", cmd);
		cmd_help();
	}
}

/* ---------------- proc 接口 ---------------- */

static ssize_t gh_proc_read(struct file *f, char __user *ubuf, size_t n, loff_t *off)
{
	ssize_t ret;

	if (mutex_lock_interruptible(&gh_lock))
		return -ERESTARTSYS;
	ret = simple_read_from_buffer(ubuf, n, off, gh_buf, gh_len);
	mutex_unlock(&gh_lock);
	return ret;
}

static ssize_t gh_proc_write(struct file *f, const char __user *ubuf, size_t n, loff_t *off)
{
	char kbuf[256];
	size_t len = (n < sizeof(kbuf) - 1) ? n : sizeof(kbuf) - 1;

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	while (len && (kbuf[len - 1] == '\n' || kbuf[len - 1] == '\r'))
		kbuf[--len] = '\0';
	if (!len)
		return n;

	if (mutex_lock_interruptible(&gh_lock))
		return -ERESTARTSYS;
	dispatch(kbuf);
	mutex_unlock(&gh_lock);
	return n;
}

static const struct proc_ops gh_proc_fops = {
	.proc_read = gh_proc_read,
	.proc_write = gh_proc_write,
};

static struct proc_dir_entry *gh_entry;

static int __init ghvmprobe_init(void)
{
	gh_buf[0] = '\0';
	gh_len = 0;
	gh_entry = proc_create(PROBE_NAME, 0644, NULL, &gh_proc_fops);
	if (!gh_entry) {
		pr_err(DRV_TAG "proc_create failed\n");
		return -ENOMEM;
	}
	pr_info(DRV_TAG "loaded; /proc/%s ready\n", PROBE_NAME);
	return 0;
}

static void __exit ghvmprobe_exit(void)
{
	if (gh_entry)
		remove_proc_entry(PROBE_NAME, NULL);
	pr_info(DRV_TAG "unloaded\n");
}

module_init(ghvmprobe_init);
module_exit(ghvmprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gunyah HLOS-side VM lifecycle probe (/proc interface, read-only first)");
MODULE_AUTHOR("dsh");
