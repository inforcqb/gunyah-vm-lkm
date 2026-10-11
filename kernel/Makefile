# 外部模块：ghvmprobe（Gunyah HLOS 侧 VM 生命周期探针）
#
# 未定义符号（vendor 驱动未导出 / CRC / 命名空间不匹配的）不在这里补，交给
# ksud insmod / susfs_insmod 在用户态按名填地址（SHN_UNDEF → SHN_ABS）。
# 因此 modpost 必须容忍未定义符号（否则链接阶段就失败）。
KBUILD_MODPOST_WARN := 1

obj-m += ghvmprobe.o
