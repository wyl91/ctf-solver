# ctf-solver

> CTF (Capture The Flag) 竞赛全方向解题辅助 Skill，适用于 [CodeBuddy](https://www.codebuddy.ai/) IDE。
> 覆盖 **Web、Crypto、Misc、Reverse、Pwn** 五大方向：分类识别流程 + 各方向解题方法论 + 可直接执行的攻击脚本。

## 功能特性

### 五方向解题参考（按需加载，不占上下文）

| 方向 | 内容 |
|------|------|
| **Web** | SQL 注入、命令执行、文件上传、反序列化（PHP/Java/Python）、SSTI、SSRF、文件包含、JWT、XSS、PHP trick 速查表、框架漏洞（ThinkPHP/Log4j/Shiro/Fastjson/Struts2） |
| **Crypto** | RSA 攻击决策表（13 种特征→攻击映射）、古典密码、编码识别表、哈希碰撞、格密码、随机数攻击 |
| **Misc** | 文件分析、图片/音频隐写、压缩包（伪加密/爆破/明文攻击）、流量分析（Wireshark 过滤器、USB 流量）、内存取证（Volatility）、磁盘取证 |
| **Reverse** | 脱壳、反调试/反虚拟机、花指令、VM 保护、z3/angr 求解、pyinstaller/.NET/APK/WASM 等非常规逆向 |
| **Pwn** | checksec 绕过、栈溢出 ROP、ret2libc、格式化字符串、堆利用路线（glibc 2.23→2.34+）、SROP、ORW、one_gadget |

### 捆绑脚本（纯标准库，开箱即用）

```
scripts/
├── rsa_attacks.py   # RSA 攻击集：小指数/Wiener/Fermat/共模/共享素数/Pollard p-1/dp泄露/factordb
├── decode.py        # 14 种编解码 + 编码自动识别 + 古典密码频率分析
├── file_triage.py   # 文件取证：魔数/嵌入数据/flag搜索/PNG宽高CRC/ZIP伪加密检测
└── pwn_template.py  # pwntools exploit 模板（需 pip install pwntools）
```

## 安装

### 方式一：手动安装（推荐）

1. 下载本仓库（Clone 或 Download ZIP）
2. 将 `ctf-solver` 整个文件夹复制到 CodeBuddy 的用户级 skills 目录：

```
Windows: %USERPROFILE%\.codebuddy\skills\ctf-solver\
Linux/macOS: ~/.codebuddy/skills/ctf-solver/
```

3. 重启 CodeBuddy，skill 自动生效

> 也可以放到项目级目录 `.codebuddy/skills/ctf-solver/`，仅对该项目生效，适合团队共享。

### 方式二：从 zip 安装

如果拿到的是打包好的 `ctf-solver.zip`，解压后同样放入上述目录即可。

## 使用

安装后无需任何命令，直接在 CodeBuddy 对话中给出题目，skill 会自动触发：

```
我有一个 RSA 题目: n=..., e=3, c=...          → 自动识别 → 小指数攻击
@flow.pcapng 解出 flag                        → 加载 Misc 流量分析流程
这个 exe 是逆向题，帮我分析                    → 反汇编分析流程
```

skill 的工作流：**识别方向 → 加载对应参考文档 → 调用脚本攻击 → 输出 flag**。

### 脚本也可独立使用

```bash
# RSA 小指数攻击
python scripts/rsa_attacks.py small-e --e 3 --c 970299 --n 100160063

# RSA Wiener 攻击
python scripts/rsa_attacks.py wiener --e 7931885 --n 100160063 --c 21104351

# 编码自动识别
python scripts/decode.py identify "ZmxhZ3t0ZXN0fQ=="

# 文件取证
python scripts/file_triage.py suspicious.png
```

## Skill 结构

```
ctf-solver/
├── SKILL.md          # 主文档：方向识别流程 + 脚本调度（入口）
├── references/       # 五方向解题方法论（按需加载）
│   ├── web.md
│   ├── crypto.md
│   ├── misc.md
│   ├── reverse.md
│   └── pwn.md
└── scripts/          # 可直接执行的攻击/分析脚本
    ├── rsa_attacks.py
    ├── decode.py
    ├── file_triage.py
    └── pwn_template.py
```

## 实战示例

- [x] Reverse 迷宫题：从 exe 提取 5×5 迷宫 + BFS 求路径 → `flag{222441144222}`
- [x] Misc 流量题：tshark 导出 HTTP 对象 → 提取 JPEG 尾部附加明文 → `flag{da73d889...}`

## License

MIT
