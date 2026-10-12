---
name: ctf-solver
description: CTF (Capture The Flag) 竞赛全方向解题辅助技能，覆盖 Web、Crypto、Misc、Reverse、Pwn 五大方向。当用户给出 CTF 题目、附件、加密脚本、流量包、二进制文件、RSA 参数（n/e/c/p/q/dp）、隐写图片、压缩包等，或提到"解题"、"flag"、"ctf"、某方向题目时使用此技能。提供分类识别流程、各方向解题方法论、攻击手法速查表，以及可直接执行的 RSA 攻击、编解码、文件分析脚本。
---

# CTF Solver

## Overview

CTF 竞赛解题辅助技能。根据题目附件和描述判断题目方向（Web/Crypto/Misc/Reverse/Pwn），加载对应方向的解题方法论参考文档，调用捆绑脚本快速执行常见攻击和分析操作，逐步推导直至获得 flag。

## 核心工作流

### 第 1 步：识别题目方向

按以下特征判断方向，然后**必须加载对应的参考文档**（用 read_file 读取）：

| 特征 | 方向 | 参考文档 |
|------|------|---------|
| URL、HTTP 请求、网站源码、PHP/Python Web 代码 | Web | `references/web.md` |
| n/e/c 等 RSA 参数、加密脚本、密文、古典密码特征 | Crypto | `references/crypto.md` |
| 图片/音频/压缩包/pcap 流量包/内存镜像、"杂项"附件 | Misc | `references/misc.md` |
| 二进制可执行文件（ELF/PE/APK）、要求找注册码/密码 | Reverse | `references/reverse.md` |
| 带监听端口的二进制（nc/服务器）、libc 附件、需写 exploit | Pwn | `references/pwn.md` |

方向不明时（如一个二进制文件既可能是 Reverse 也可能是 Pwn）：有远程交互环境或附件含 libc → Pwn；纯本地校验 → Reverse。可同时加载两份参考。

### 第 2 步：执行对应方向的解题流程

各参考文档包含：检查清单、攻击手法速查表、工具命令、绕过技巧。按文档中的流程逐项尝试，优先尝试文档中标"常见/必试"的手法。

### 第 3 步：调用捆绑脚本

所有脚本位于 `scripts/` 目录，纯标准库实现（`pwn_template.py` 除外，需 pwntools），可直接用 python 执行：

**`scripts/rsa_attacks.py` — RSA 攻击工具集**
- 用法见脚本头部注释。支持：小指数攻击、Wiener、Fermat 分解、共模攻击、共享素数分解、Pollard p-1、dp 泄露、factordb 在线查询、已知 d 解密。
- 参数支持十进制和 `0x` 十六进制。
- 收到 RSA 参数后，先对照 `references/crypto.md` 的"RSA 攻击决策表"选择攻击方式，再调用对应子命令。

**`scripts/decode.py` — 多合一编解码**
- 子命令：rot13/rot/b64/b32/b85/hex/bin/dec/url/morse/bacon/tapcode/xor/freq/identify。
- 收到不明编码时先用 `identify` 自动猜测，再用对应子命令解码。`freq` 用于古典密码频率分析。

**`scripts/file_triage.py` — Misc 文件分析**
- 用法：`python file_triage.py <文件>`。
- 自动完成：魔数识别（文件头是否损坏）、嵌入数据检测（binwalk 类）、flag 模式搜索、可疑字符串提取、PNG 宽高 CRC 校验（检测宽高篡改）、ZIP 伪加密检测。
- 收到任何二进制附件时**首先运行此脚本**，根据输出决定后续步骤（binwalk 提取、zsteg、steghide 等，见 `references/misc.md`）。

**`scripts/pwn_template.py` — pwntools 模板**
- 需 `pip install pwntools`。Pwn 题编写 exploit 的起点模板，含 ret2libc、泄露、格式化字符串探测的现成函数。

脚本运行失败或环境缺依赖时：读脚本源码理解算法，在对话中改写为适应具体题目的版本再执行。

### 第 4 步：结果处理

- 解出明文后检查是否为嵌套编码（明文还是 Base64/hex → 继续用 `decode.py` 解）。
- 得到 flag 后直接输出给用户。
- 尝试完参考文档所有手法仍未解出时：列出已尝试的手法和排除的原因，给出下一步建议（如需要外部工具 sage/IDA/不可用的环境）。

## 注意事项

- 附件文件先放工作区再用脚本分析，路径使用绝对路径。
- 网络类工具（factordb 查询）无网络时自动跳过，改用本地攻击。
- 交互式题目（nc 连接、反弹 shell）优先用 pwntools 写脚本而非手动命令。
- 输出给用户的解密结果必须同时给出明文和 flag（若有）。
