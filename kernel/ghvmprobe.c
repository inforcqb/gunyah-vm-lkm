// SPDX-License-Identifier: GPL-2.0
/*
 * ghvmprobe.c — Gunyah HLOS 侧 VM 生命周期探针（分级、只读优先）
 *
 * 结论背景（2026-10-11 静态+设备侦察）：
 *   - RM(EL2) 对 caller vmid==3(HLOS) 开放 VM 生命周期服务：VM_ALLOC_VMID(0x56000001)、
 *     VM_CONFIG_IMAGE(0x56000009)、VM_AUTH_IMAGE、VM_INIT(0x5600000b)、VM_START(0x56000004)。
 *   - vmid 分配池在 RM 初始化里硬编码为 {45,49,50}（rm2.elf @0x35ae0/0x35ae4）。
 *   - VM_CONFIG_IMAGE 的 auth_mech 由请求报文自己填（payload[+2]），0 = 免认证分支。
 *   - 状态机：5=LOAD(alloc 后) → 6=AUTH(config_image 后) → 1=INIT → 2=READY → 3=RUNNING。
 *   - 这些服务在 HLOS 侧由 vendor 驱动导出：gh_rm_vm_alloc_vmid / config_image /
 *     auth_image / init / start / stop / dealloc_vmid / get_vmid / get_vm_id_info。
 *
 * 本模块只做分级探测，默认 stage=0（不碰设备状态）：
 *   stage=0 : 仅 pr_info，验证构建/加载链路
 *   stage=1 : 只读探测（名字→枚举、vmid 反查、gh_rm_get_vm_id_info）
 *   stage=2 : gh_rm_vm_alloc_vmid(name, vmid=0) —— 只分配，不 config/不 start
 *
 * 未定义符号（vendor 驱动未导出或 CRC/命名空间不匹配的）一律"直接声明"，交给
 * ksud insmod / susfs_insmod 在用户态按名填充（SHN_UNDEF → SHN_ABS + kallsyms 地址）。
 * 加载前需临时放开 kptr_restrict（=2 时 loader 拿不到真地址，必须拒绝加载）。
 *
 * CFI：这里全部是"编译期已知符号的直接调用"（bl foo），不经过间接调用点，因此
 * 不需要 __nocfi；一旦改成"取地址再调用"，必须包 __nocfi（见 skill kernel-module-cfi）。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>

#define DRV_TAG "ghvmprobe: "

typedef u16 gh_vmid_t;
#define GH_VMID_INVAL 0xffff

/* ---- 直接声明：类型/原型必须与 vendor 驱动一致（loader 只填地址，不做类型检查）---- */
/* enum gh_vm_names 的底层类型是 int，此处按 int 声明以避免依赖未抓取的头文件 */
extern int  gh_get_vm_name(const char *str);            /* enum gh_vm_names */
extern int  gh_rm_get_vmid(int vm_name, gh_vmid_t *vmid);
extern int  gh_rm_get_vm_id_info(gh_vmid_t vmid);
extern int  gh_rm_vm_alloc_vmid(int vm_name, int *vmid);

static int stage = 0;
module_param(stage, int, 0644);
MODULE_PARM_DESC(stage, "0=print only, 1=read-only probes, 2=alloc vmid");

static const char *const name_tab[] = {
	"trustedvm", "oemvm", "microdroid", "cpusys", "hlos", "host",
};

static void probe_names(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(name_tab); i++) {
		int nm = gh_get_vm_name(name_tab[i]);
		gh_vmid_t vmid = GH_VMID_INVAL;
		int ret;

		pr_info(DRV_TAG "name '%s' -> enum %d\n", name_tab[i], nm);
		if (nm < 0)
			continue;
		ret = gh_rm_get_vmid(nm, &vmid);
		pr_info(DRV_TAG "  gh_rm_get_vmid(enum %d) ret=%d vmid=%u\n",
			nm, ret, (unsigned)vmid);
	}
}

static void probe_vmid_info(void)
{
	int ret;

	/* vmid 3 = HLOS 自己；只读的 GET_ID 查询，用来证明"模块能借驱动发 RM RPC" */
	ret = gh_rm_get_vm_id_info(3);
	pr_info(DRV_TAG "gh_rm_get_vm_id_info(3) ret=%d\n", ret);
}

static void probe_alloc(void)
{
	int vmid = 0;		/* 0 => 让 RM 从池里挑（预期 45） */
	int ret;

	ret = gh_rm_vm_alloc_vmid(0, &vmid);
	pr_info(DRV_TAG "gh_rm_vm_alloc_vmid(name=0) ret=%d vmid=%d\n", ret, vmid);
}

static int __init ghvmprobe_init(void)
{
	pr_info(DRV_TAG "loaded, stage=%d\n", stage);

	switch (stage) {
	case 0:
		pr_info(DRV_TAG "stage 0: build/load chain OK\n");
		break;
	case 1:
		probe_names();
		probe_vmid_info();
		break;
	case 2:
		probe_names();
		probe_alloc();
		break;
	default:
		pr_warn(DRV_TAG "unknown stage %d\n", stage);
		break;
	}
	return 0;
}

static void __exit ghvmprobe_exit(void)
{
	pr_info(DRV_TAG "unloaded\n");
}

module_init(ghvmprobe_init);
module_exit(ghvmprobe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gunyah HLOS-side VM lifecycle probe (read-only first)");
MODULE_AUTHOR("dsh");
