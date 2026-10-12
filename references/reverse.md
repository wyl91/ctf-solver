# Reverse 方向解题参考

## 1. 通用流程

1. `file` 确认架构（x86/x64/ARM/MIPS）
2. 查壳：ExeinfoPe / DIE（Detect It Easy）
3. 有壳先脱壳（UPX：`upx -d`；其他壳用 x64esp/OEP）
4. 静态分析：IDA / Ghidra / Binary Ninja（反编译看 main）
5. 动态调试：x64dbg / gdb / lldb
6. 定位校验逻辑（strcmp/比较循环），提取算法，写脚本正向求解

## 2. 壳与脱壳

| 壳 | 处理 |
|----|------|
| UPX | `upx -d` 或手动 |
| VMP/Themida | 动态 trace + 对抗脚本，耗时长 |
| ASPack/PECompact | ESP 定律/OEP 查找 |
| .NET (dnSpy) | 直接 dnSpy 反编译，de4dot 去混淆 |
| Python 打包 (pyinstaller) | `pyinstxtractor` 解包 → uncompyle6/pycdc 反编译 |
| Nuitka/py2exe | pyinstxtractor + pycdc |
| Java | jadx / jd-gui / CFR；混淆用 proton/jar-deobfuscator |
| APK | jadx-gui / apktool；梆梆/360 加固脱壳（FRIDA-DEXDump） |
| Go | IDA Go 插件 / `go-strings`；符号还原 |
| Rust | Ghidra + 符号 |

## 3. 常见考点

### 反调试/反虚拟机
```c
// 常见反调试 API (Windows)
IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
// 时间差检测: rdtsd/GetTickCount 前后差值
// 检测: FindWindow("OLLYDBG"), 虚拟机注册表/网卡 MAC
// Linux: ptrace(PTRACE_TRACEME) 失败表示被调试
// 绕过: patch 判断分支 / ScyllaHide 插件 / LD_PRELOAD hook
```

### 字符串/算法混淆
- 自定义 Base64 变表（异或 0x20、换表）
- 简单异或/加减（注意逐字节找规律）
- 逆序/位运算混淆
- TEA/XTEA/XXTEA/RC4/AES 硬编码密钥（识别常量：`0x9E3779B9` → TEA 系）
- 自定义 VM（虚拟机保护）：提取 opcode 表，写 disassembler
- 控制流平坦化：deflat / 手动恢复
- SMC 自修改代码：动态 dump

### 花指令
典型 `jmp $+x` 跳入指令中间 → NOP 掉或用脚本清理，使 IDA 正常反编译

### CRC/哈希校验
输入校验与计算结果比对 → 逆向算法正向计算，而不是爆破

## 4. 动态调试技巧

```bash
# gdb
gdb ./crack
b main / b *0x401234
r < input.txt
x/32xw $rsp
# pwndbg/gef 增强调试
# Python ELF: python3 里 import ctypes 调 so：ctypes.CDLL('./lib.so')
```

```bash
# Windows
# x64dbg: 常用命令 bp, 跟随堆栈, 硬件断点 on memory access
# 条件断点: bp addr, condition
```

## 5. 非常规文件逆向

| 类型 | 工具 |
|------|------|
| Lua 脚本加密 | unluac / luadec（先看文件头 `\x1bLua`） |
| WASM | wasm2c / wasm-decompile（在线 wasdk） |
| Scratch | 解压 sb3 看 JSON |
| 易语言 | OD + E-code 插件 |
| Unity IL2CPP | Il2CppDumper + IDA |
| Godot | gdsdecomp |
| GameMaker / RPG Maker | 专门工具 |
| Chip8 / 自定义 VM | 写模拟器或手动解码 |

## 6. 快速定位技巧

1. **找字符串**：Shift+F12 看字符串表，"Wrong"/"Correct"/"flag" 交叉引用
2. **找 main**：入口点 → `__libc_start_main` 第一参数；Windows 看 WinMain
3. **比较函数**：strcmp/memcmp/自定义逐字符比较 → 交叉引用定位
4. **方程求解**：输入长、约束多 → z3-solver 建模
```python
from z3 import *
flag = [Int(f'c{i}') for i in range(32)]
s = Solver()
# 添加从逆向中提取的约束...
print(s.check())
m = s.model()
print(''.join(chr(m[c].as_long()) for c in flag))
```
5. **符号执行**：angora/angr（输入未知、求到达 success 的输入）
```python
import angr
p = angr.Project('./crack', auto_load_libs=False)
sim = p.factory.entry_state()
sm = p.factory.simgr(sim)
sm.explore(find=lambda st: b'Correct' in st.posix.dumps(1))
print(sm.found[0].posix.dumps(0))
```
