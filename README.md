# gunyah-vm-lkm — Gunyah HLOS 侧 VM 生命周期探针

目标：在 **PJA110（SM8550 / kalama，EL2 = Gunyah 3）** 上，用 **HLOS(root, vmid=3)** 走 Gunyah
的**标准 API** 创建并启动一个次级 VM（Ubuntu kernel），全程不绕过、不打洞。

## 为什么现在认为可行（2026-10-11 静态 + 设备侦察）

1. **RM(EL2) 对 caller vmid==3 开放 VM 生命周期服务**（反汇编 rm2.elf，分派器 `0x37880`）：
   `0x56000001 VM_ALLOC_VMID`（caller==3 专用分支）、`0x56000009 VM_CONFIG_IMAGE`（非 3 直接失败）、
   `VM_AUTH_IMAGE`（要求 state==6）、`0x5600000b VM_INIT`、`0x56000004/05 VM_START/STOP`（要求 owner==caller）。
2. **vmid 分配池硬编码给 HLOS**：RM 初始化 `0x35ae0-0x35ae4` 把 `[0x4e168]` 写成
   `0x0006200000000000` ⇒ 池 = **{45,49,50}**；ACL 白名单同时含 `{10,45,49,50}`（正好能把自己的内存
   share 给自己的子 VM）。
3. **auth_mech 由请求方自己填**：`VM_CONFIG_IMAGE` 报文 `+2` 就是 auth_mech，0 = 免认证分支
   （`0x46a10 cbz w2 → 无认证路径`）。驱动上层 `gh_vm_configure()` 只允许 `GH_VM_AUTH_PIL_ELF`，
   但底层导出的 `gh_rm_vm_config_image(vmid, auth_mech, ...)` 直接接受 0。
4. **报文里的 `mem_handle` 是我们自己的内存 parcel 句柄**，不是"平台预置配置条目"：
   `struct gh_vm_config_image_req_payload { vmid; auth_mech; mem_handle; image_off/size; dtb_off/size; }`
   与反汇编逐字段一致 ⇒ 只要自己 `gh_rm_mem_lend/donate` 一块 RAM 即可。
5. **状态机**（`vm+0xc8`，与官方宏吻合）：5=LOAD →（CONFIG_IMAGE）6=AUTH → 1=INIT → 2=READY →（START）3=RUNNING，
   8=INIT_FAILED。
6. **HLOS 侧驱动导出了全部所需 API**（设备 `/proc/kallsyms` 的 `gh_rm_drv` 导出清单见
   `kernel/gh_rm_drv_exports.txt`）：`gh_rm_vm_alloc_vmid / config_image / auth_image / init / start /
   dealloc_vmid / get_vmid / get_vm_name / get_vm_id_info / mem_lend / mem_donate / console_open …`。
7. **console 通道已就位**：`hvc_gunyah` 已加载，`/dev/hvc0..63` 存在（`vtermno = vm_name + cookie`）。

## 未导出符号怎么处理（本项目约定）

对"未导出 / 导出被裁剪 / CRC 或命名空间不匹配"的符号：**直接在源码里 `extern` 声明**，不做任何包装，
由 **`ksud insmod`（或 `susfs_insmod`）在用户态按名解析**：把 ELF 里每个 `SHN_UNDEF` 原地改成
`SHN_ABS` + 从 `/proc/kallsyms` 取到的绝对地址，从而跳过 `Unknown symbol`、`import_ns`、CRC 与 KMI 门。

- 因此 Makefile 必须 `KBUILD_MODPOST_WARN := 1`，否则 modpost 会因未定义符号直接失败。
- **加载前**要临时把 `kptr_restrict` 从 2 改成 0（=2 时 `/proc/kallsyms` 地址全 0，loader 必须拒绝加载），
  加载后还原。
- 我们这里全部是**直接调用**（`bl gh_rm_vm_alloc_vmid`）⇒ 不走 CFI 间接调用检查，**不需要 `__nocfi`**；
  一旦改成"取地址存函数指针再调"，必须包 `__nocfi`（CFI 铁律）。

## 分级探测（默认 stage=0，什么都不做）

| stage | 行为 | 副作用 |
|---|---|---|
| 0 | 只 `pr_info` | 无（验证构建+加载链路） |
| 1 | 名字→枚举、`gh_rm_get_vmid`、`gh_rm_get_vm_id_info(3)` | 只读 |
| 2 | `gh_rm_vm_alloc_vmid(name, vmid=0)` | 占用一个 vmid 位（可 `dealloc` 归还） |

后续（另开 stage）：`mem_lend` → `config_image(auth=0, mem_handle, image/dtb 偏移)` → `vm_init` → `vm_start`。

## 构建

CI 用 DDK 容器（与设备 `5.15.180-android13-8-o-01179` 同系）：
`ghcr.io/ylarod/ddk-min:android13-5.15-20260828`，`make -C $KDIR M=$PWD/kernel modules`。
CI 带一道**硬门**：`.ko` 的每个未定义符号都必须在 `kernel/gh_rm_drv_exports.txt` 里，
否则 `::error::` 失败（名字写错比功能失效更致命）。

## 加载 / 验证

```sh
# 1) 放开 kptr_restrict（loader 需要真地址）
echo 0 > /proc/sys/kernel/kptr_restrict
# 2) 装模块（loader 打印 undefined symbols: N → resolved N/N）
ksud insmod ghvmprobe.ko stage=1
# 3) 看结果
dmesg | grep ghvmprobe
ls -d /sys/module/ghvmprobe        # 自隐藏模块用 lsmod 看不到
# 4) 还原
rmmod ghvmprobe 2>/dev/null; echo 2 > /proc/sys/kernel/kptr_restrict
```

## 风险

- 首次 insmod 有崩溃/重启可能 ⇒ 先 stage=0，再 stage=1，最后 stage=2。
- 不碰 QRTR（那条路有已知 32-bit 回绕 + `panic_on_rcu_stall=1` 的重启风险）、不碰 TEE。
- 设备上 `/data/local/tmp` 有大量历史文件，一律不动。
