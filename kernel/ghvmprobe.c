// SPDX-License-Identifier: GPL-2.0
/*
 * ghvmprobe.c — Gunyah HLOS 侧 VM 生命周期探针（/proc 交互式）
 *
 * 用法：
 *   insmod ghvmprobe.ko                 # 只注册 /proc/ghvmprobe
 *   echo <cmd> > /proc/ghvmprobe ; cat /proc/ghvmprobe
 *
 * 命令：
 *   help / clear
 *   names                     名字映射 + 各枚举 vmid 占用（只读）
 *   rev <vmid>                vmid -> 枚举（只读）
 *   idinfo <vmid>             gh_rm_get_vm_id_info（只读 RPC）
 *   alloc [enum]              gh_rm_vm_alloc_vmid(enum, vmid=0)  → 本机实测返回 45
 *   dealloc <vmid>            gh_rm_vm_dealloc_vmid
 *   status <vmid>             gh_rm_vm_get_status
 *   load <img> <dtb> [vmid]   CMA 分配 → 读入镜像/DTB → gh_rm_mem_lend(ACL={目标vmid}) →
 *                             gh_rm_vm_config_image(vmid, auth_mech=0, ...)   ← 免认证分支
 *   init <vmid> / start <vmid> / stop <vmid>
 *
 * 事实依据（本机实测 + 本地源码/反汇编）：
 *   - RM 对 caller vmid==3(HLOS) 开放 VM 生命周期服务；vmid 池硬编码 {45,49,50}（实测拿到 45）。
 *   - VM_CONFIG_IMAGE 报文：{u16 vmid; u16 auth_mech; u32 mem_handle; u64 image_off/size; u64 dtb_off/size}
 *     （40 字节）；auth_mech=0 走 RM 的免认证分支。GH_VM_AUTH_PIL_ELF=1 才需要 pas_id+签名认证。
 *   - 状态机（vm+0xc8，与 gh_rm_drv.h 宏一致）：5=LOAD →6=AUTH →1=INIT →2=READY →3=RUNNING，8=INIT_FAILED。
 *   - 内存可执行镜像的样板是驱动自己的 gh_provide_mem()（gh_main.c:474）：
 *     dma_alloc_coherent(CMA) + acl{vmid, X|W|R} + sgl{phys,size} + gh_rm_mem_lend(...)。
 *
 * 未定义符号直接声明，由 ksud insmod 在用户态按名填地址（SHN_UNDEF → SHN_ABS）；
 * 全部是直接调用（编译期已知符号），不走 CFI 间接调用检查，无需 __nocfi。
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
#include <linux/file.h>
#include <linux/stdarg.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/mm.h>

#define DRV_TAG "ghvmprobe: "
#define PROBE_NAME "ghvmprobe"
#define OUT_SZ 16384

typedef u16 gh_vmid_t;
#define GH_VMID_INVAL 0xffff
#define GH_VM_MAX_ENUM 6

#define GH_RM_MEM_TYPE_NORMAL 0
#define GH_RM_ACL_X BIT(0)
#define GH_RM_ACL_W BIT(1)
#define GH_RM_ACL_R BIT(2)

struct gh_acl_entry {
	u16 vmid;
	u8 perms;
	u8 reserved;
} __packed;

struct gh_sgl_entry {
	u64 ipa_base;
	u64 size;
} __packed;

struct gh_acl_desc {
	u32 n_acl_entries;
	struct gh_acl_entry acl_entries[];
} __packed;

struct gh_sgl_desc {
	u16 n_sgl_entries;
	u16 reserved;
	struct gh_sgl_entry sgl_entries[];
} __packed;

struct gh_vm_status {
	u8 vm_status;
	u8 os_status;
	u16 app_status;
} __packed;

/* ---- 直接声明：名字/原型必须与 vendor 驱动一致 ---- */
extern int gh_get_image_name(const char *str);
extern int gh_get_vm_name(const char *str);
extern int gh_rm_get_vmid(int vm_name, gh_vmid_t *vmid);
extern int gh_rm_get_vm_name(gh_vmid_t vmid, int *vm_name);
extern int gh_rm_get_vm_id_info(gh_vmid_t vmid);
extern int gh_rm_vm_alloc_vmid(int vm_name, int *vmid);
extern int gh_rm_vm_dealloc_vmid(gh_vmid_t vmid);
extern int gh_rm_mem_lend(u8 mem_type, u8 flags, u32 label,
			  struct gh_acl_desc *acl_desc,
			  struct gh_sgl_desc *sgl_desc,
			  void *mem_attr_desc, u32 *mem_handle);
extern int gh_rm_vm_config_image(gh_vmid_t vmid, u16 auth_mech, u32 mem_handle,
				 u64 image_offset, u64 image_size,
				 u64 dtb_offset, u64 dtb_size);
extern int gh_rm_vm_init(gh_vmid_t vmid);
extern int gh_rm_vm_start(int vmid);
extern int gh_rm_vm_stop(gh_vmid_t vmid, u32 stop_reason, u8 flags);
extern struct gh_vm_status *gh_rm_vm_get_status(gh_vmid_t vmid);

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
static const char *const status_names[] = {
	"NO_STATE", "INIT", "READY", "RUNNING", "PAUSED",
	"LOAD", "AUTH", "?", "INIT_FAILED", "EXITED",
	"RESETTING", "RESET",
};

static DEFINE_MUTEX(gh_lock);
static char gh_buf[OUT_SZ];
static size_t gh_len;

/* 借给次级 VM 的 CMA 缓冲 */
static struct platform_device *ghvm_pdev;
static void *vm_membuf;
static dma_addr_t vm_membuf_dma;
static size_t vm_membuf_size;
static u32 vm_mem_handle;
static int vm_target_vmid;
static size_t vm_image_size, vm_dtb_off, vm_dtb_size;

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

/* ---------------- 只读 / 分配类命令 ---------------- */

static void cmd_help(void)
{
	out("commands:\n");
	out("  help | clear\n");
	out("  names                    name maps + per-enum vmid occupancy\n");
	out("  rev <vmid>               vmid -> enum\n");
	out("  idinfo <vmid>            gh_rm_get_vm_id_info\n");
	out("  alloc [enum]             gh_rm_vm_alloc_vmid(enum, 0)\n");
	out("  dealloc <vmid>           gh_rm_vm_dealloc_vmid\n");
	out("  status <vmid>            gh_rm_vm_get_status\n");
	out("  load <img> <dtb> [vmid]  CMA + mem_lend + config_image(auth=0)\n");
	out("  init <vmid> | start <vmid> | stop <vmid>\n");
	out("  meminfo                  CMA buffer state\n");
}

static void cmd_names(void)
{
	int i;

	out("-- name maps --\n");
	for (i = 0; i < ARRAY_SIZE(image_names); i++)
		out("  image '%s' -> %d ; vm_name '%s' -> %d\n",
		    image_names[i], gh_get_image_name(image_names[i]),
		    vm_names[i], gh_get_vm_name(vm_names[i]));

	out("-- per-enum vmid (local table) --\n");
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

	out("gh_rm_get_vm_name(%d) -> ret=%d enum=%d %s\n", vmid, ret, nm,
	    (nm >= 0 && nm < GH_VM_MAX_ENUM) ? enum_names[nm] : "");
}

static void cmd_idinfo(int vmid)
{
	out("gh_rm_get_vm_id_info(%d) -> ret=%d\n", vmid,
	    gh_rm_get_vm_id_info((gh_vmid_t)vmid));
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
	out("alloc: enum %d (%s), requesting vmid=0\n", i, enum_names[i]);
	ret = gh_rm_vm_alloc_vmid(i, &vmid);
	out("gh_rm_vm_alloc_vmid(%d) -> ret=%d vmid=%d\n", i, ret, vmid);
}

static void cmd_dealloc(int vmid)
{
	out("gh_rm_vm_dealloc_vmid(%d) -> ret=%d\n", vmid,
	    gh_rm_vm_dealloc_vmid((gh_vmid_t)vmid));
}

static void cmd_status(int vmid)
{
	struct gh_vm_status *st = gh_rm_vm_get_status((gh_vmid_t)vmid);

	if (!st) {
		out("gh_rm_vm_get_status(%d) -> NULL\n", vmid);
		return;
	}
	if (IS_ERR(st)) {
		out("gh_rm_vm_get_status(%d) -> ERR %ld\n", vmid, PTR_ERR(st));
		return;
	}
	out("vmid %d: vm_status=%u(%s) os_status=%u app_status=0x%x\n",
	    vmid, st->vm_status,
	    (st->vm_status < ARRAY_SIZE(status_names)) ? status_names[st->vm_status] : "?",
	    st->os_status, st->app_status);
}

/* ---------------- 镜像加载 ---------------- */

static int read_file(const char *path, void *dst, size_t cap, size_t *got)
{
	struct file *f = filp_open(path, O_RDONLY, 0);
	loff_t pos = 0;
	ssize_t n;

	if (IS_ERR(f))
		return PTR_ERR(f);
	n = kernel_read(f, dst, cap, &pos);
	filp_close(f, NULL);
	if (n < 0)
		return (int)n;
	*got = (size_t)n;
	return 0;
}

static int file_size(const char *path, size_t *sz)
{
	struct file *f = filp_open(path, O_RDONLY, 0);

	if (IS_ERR(f))
		return PTR_ERR(f);
	*sz = i_size_read(file_inode(f));
	filp_close(f, NULL);
	return 0;
}

static void cmd_load(const char *imgp, const char *dtbp, int vmid)
{
	size_t isz = 0, dsz = 0, need, dtb_off;
	struct gh_acl_desc *acl;
	struct gh_sgl_desc *sgl;
	struct platform_device *pdev = ghvm_pdev;
	int ret;

	ret = file_size(imgp, &isz);
	if (ret) {
		out("stat %s failed %d\n", imgp, ret);
		return;
	}
	ret = file_size(dtbp, &dsz);
	if (ret) {
		out("stat %s failed %d\n", dtbp, ret);
		return;
	}
	dtb_off = PAGE_ALIGN(isz);
	need = dtb_off + PAGE_ALIGN(dsz);
	out("image %s = %zu bytes, dtb %s = %zu bytes, need %zu bytes\n",
	    imgp, isz, dtbp, dsz, need);

	if (vm_membuf && vm_membuf_size < need) {
		out("freeing old CMA buffer (%zu bytes)\n", vm_membuf_size);
		dma_free_coherent(&pdev->dev, vm_membuf_size, vm_membuf,
				  vm_membuf_dma);
		vm_membuf = NULL;
		vm_membuf_size = 0;
		vm_mem_handle = 0;
	}
	if (!vm_membuf) {
		vm_membuf = dma_alloc_coherent(&pdev->dev, need, &vm_membuf_dma,
					       GFP_KERNEL);
		if (!vm_membuf) {
			out("dma_alloc_coherent(%zu) FAILED\n", need);
			return;
		}
		vm_membuf_size = need;
	}
	out("CMA buf: virt=%p phys=%pa size=%zu\n", vm_membuf, &vm_membuf_dma,
	    vm_membuf_size);

	ret = read_file(imgp, vm_membuf, isz, &vm_image_size);
	if (ret) {
		out("read image failed %d\n", ret);
		return;
	}
	ret = read_file(dtbp, vm_membuf + dtb_off, dsz, &vm_dtb_size);
	if (ret) {
		out("read dtb failed %d\n", ret);
		return;
	}
	vm_dtb_off = dtb_off;
	out("loaded: image=%zu @0  dtb=%zu @%zu\n", vm_image_size, vm_dtb_size,
	    vm_dtb_off);

	acl = kzalloc(sizeof(*acl) + sizeof(struct gh_acl_entry), GFP_KERNEL);
	sgl = kzalloc(sizeof(*sgl) + sizeof(struct gh_sgl_entry), GFP_KERNEL);
	if (!acl || !sgl) {
		kfree(acl);
		kfree(sgl);
		out("alloc desc failed\n");
		return;
	}
	acl->n_acl_entries = 1;
	acl->acl_entries[0].vmid = (u16)vmid;
	acl->acl_entries[0].perms = GH_RM_ACL_X | GH_RM_ACL_W | GH_RM_ACL_R;
	sgl->n_sgl_entries = 1;
	sgl->sgl_entries[0].ipa_base = (u64)vm_membuf_dma;
	sgl->sgl_entries[0].size = vm_membuf_size;

	ret = gh_rm_mem_lend(GH_RM_MEM_TYPE_NORMAL, 0, 0, acl, sgl, NULL,
			     &vm_mem_handle);
	out("gh_rm_mem_lend(acl vmid=%d perms=0x%x, phys=%pa size=%zu) -> ret=%d handle=0x%x\n",
	    vmid, acl->acl_entries[0].perms, &vm_membuf_dma, vm_membuf_size,
	    ret, vm_mem_handle);
	kfree(acl);
	kfree(sgl);
	if (ret) {
		out("mem_lend failed, aborting config\n");
		return;
	}
	vm_target_vmid = vmid;

	ret = gh_rm_vm_config_image((gh_vmid_t)vmid, 0, vm_mem_handle,
				    0, vm_image_size, vm_dtb_off, vm_dtb_size);
	out("gh_rm_vm_config_image(vmid=%d, auth_mech=0, handle=0x%x, img=0/%zu, dtb=%zu/%zu) -> ret=%d\n",
	    vmid, vm_mem_handle, vm_image_size, vm_dtb_off, vm_dtb_size, ret);
	cmd_status(vmid);
}

static void cmd_init(int vmid)
{
	out("gh_rm_vm_init(%d) -> ret=%d\n", vmid, gh_rm_vm_init((gh_vmid_t)vmid));
	cmd_status(vmid);
}

static void cmd_start(int vmid)
{
	out("gh_rm_vm_start(%d) -> ret=%d\n", vmid, gh_rm_vm_start(vmid));
	cmd_status(vmid);
}

static void cmd_stop(int vmid)
{
	out("gh_rm_vm_stop(%d) -> ret=%d\n", vmid,
	    gh_rm_vm_stop((gh_vmid_t)vmid, 0, 0));
	cmd_status(vmid);
}

static void cmd_meminfo(void)
{
	out("target vmid=%d handle=0x%x\n", vm_target_vmid, vm_mem_handle);
	out("cma: virt=%p phys=%pa size=%zu\n", vm_membuf, &vm_membuf_dma,
	    vm_membuf_size);
	out("image=%zu dtb_off=%zu dtb_size=%zu\n", vm_image_size, vm_dtb_off,
	    vm_dtb_size);
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

static int next_arg(const char **p, char *outbuf, size_t n)
{
	size_t i = 0;

	while (**p == ' ')
		(*p)++;
	if (!**p)
		return -1;
	while (**p && **p != ' ' && i < n - 1)
		outbuf[i++] = *(*p)++;
	outbuf[i] = '\0';
	return 0;
}

static void dispatch(const char *cmd)
{
	const char *p = cmd;
	char a1[256], a2[256];

	out("$ %s\n", cmd);
	if (has_prefix(p, "help")) {
		cmd_help();
	} else if (has_prefix(p, "clear")) {
		gh_len = 0;
		gh_buf[0] = '\0';
	} else if (has_prefix(p, "names")) {
		cmd_names();
	} else if (has_prefix(p, "meminfo")) {
		cmd_meminfo();
	} else if (has_prefix(p, "rev")) {
		cmd_rev(simple_atoi(p + 3));
	} else if (has_prefix(p, "idinfo")) {
		cmd_idinfo(simple_atoi(p + 6));
	} else if (has_prefix(p, "dealloc")) {
		cmd_dealloc(simple_atoi(p + 7));
	} else if (has_prefix(p, "status")) {
		cmd_status(simple_atoi(p + 6));
	} else if (has_prefix(p, "stop")) {
		cmd_stop(simple_atoi(p + 4));
	} else if (has_prefix(p, "start")) {
		cmd_start(simple_atoi(p + 5));
	} else if (has_prefix(p, "init")) {
		cmd_init(simple_atoi(p + 4));
	} else if (has_prefix(p, "alloc")) {
		p += 5;
		while (*p == ' ')
			p++;
		cmd_alloc(simple_atoi(p), *p != '\0');
	} else if (has_prefix(p, "load")) {
		p += 4;
		if (next_arg(&p, a1, sizeof(a1)) || next_arg(&p, a2, sizeof(a2))) {
			out("usage: load <image> <dtb> [vmid]\n");
			return;
		}
		while (*p == ' ')
			p++;
		cmd_load(a1, a2, *p ? simple_atoi(p) : 45);
	} else {
		out("unknown command\n");
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
	char kbuf[512];
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

	ghvm_pdev = platform_device_register_simple(PROBE_NAME, -1, NULL, 0);
	if (IS_ERR(ghvm_pdev)) {
		pr_err(DRV_TAG "platform_device_register_simple failed\n");
		return PTR_ERR(ghvm_pdev);
	}
	if (dma_set_mask_and_coherent(&ghvm_pdev->dev, DMA_BIT_MASK(64)))
		dma_set_mask_and_coherent(&ghvm_pdev->dev, DMA_BIT_MASK(32));

	gh_entry = proc_create(PROBE_NAME, 0644, NULL, &gh_proc_fops);
	if (!gh_entry) {
		platform_device_unregister(ghvm_pdev);
		ghvm_pdev = NULL;
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
	if (vm_membuf) {
		pr_warn(DRV_TAG "freeing CMA buffer (handle=0x%x still lent?)\n",
			vm_mem_handle);
		dma_free_coherent(&ghvm_pdev->dev, vm_membuf_size, vm_membuf,
				  vm_membuf_dma);
		vm_membuf = NULL;
	}
	if (ghvm_pdev)
		platform_device_unregister(ghvm_pdev);
	pr_info(DRV_TAG "unloaded\n");
}

module_init(ghvmprobe_init);
module_exit(ghvmprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gunyah HLOS-side VM lifecycle probe (/proc interface)");
MODULE_AUTHOR("dsh");
