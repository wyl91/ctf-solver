# Crypto 方向解题参考

## 1. 解题流程

1. 识别密码类型（古典/现代/编码）
2. 检查所有给定参数：n, e, c, p, q, dp, dq, phi 等
3. 匹配攻击模式（见下方 RSA 攻击决策表）
4. 用 `scripts/rsa_attacks.py` 快速尝试常见攻击
5. 解出 m 后注意转 bytes：`long_to_bytes(m)`，再检查是否还需二次解码

```python
# 整数 ↔ bytes 转换（无 pycryptodome 时）
def long_to_bytes(n):
    return n.to_bytes((n.bit_length()+7)//8, 'big')
def bytes_to_long(b):
    return int.from_bytes(b, 'big')
```

## 2. RSA 攻击决策表

| 特征 | 攻击方法 |
|------|---------|
| e 很小 (3, 5, 7) 且 m^e < n | 小指数攻击，直接开 e 次方根 |
| e 很大 / 接近 n | d 很小 → Wiener 或 Boneh-Durfee |
| 两个 n 共用素数 | 共模分解 gcd(n1, n2) |
| 两组 (c, e) 同 n 同 m | 共模攻击 |
| n 可被 yafu/msieve 分解 | 直接分解（先试 factordb.com 查询） |
| p, q 接近 | Fermat 分解 |
| p-1 平滑 | Pollard p-1 |
| 给出 dp 或 dq | dp 泄露恢复 d |
| m 与 n 存在线性关系 / 已知 m 高位 | Coppersmith（sage） |
| 两条密文 m1, m2 有线性关系 | Franklin-Reiter 相关消息攻击 |
| e=1 | c 即 m |
| phi(n) 已知 | d = inverse(e, phi) |
| 多个 n，每个由相近素数生成（Batch GCD）| 批量 gcd |
| 公约数 gcd(n_i) != 1 | 共享素数 |
| n = p*q, p|q 等 | 特殊结构分解 |

### 常用脚本
```python
from Crypto.Util.number import long_to_bytes, inverse, GCD
# factordb 查询: https://factordb.com  或 pypi: factordb-pycli
```

## 3. 古典密码

| 类型 | 识别特征 | 工具 |
|------|---------|------|
| 凯撒 | 全字母位移 | `scripts/decode.py rot`、quipqiup |
| ROT13/ROT47 | 无意义字母 | 同上 |
| 维吉尼亚 | 重复密钥模式 | quipqiup、Vigenère solver（密钥长度 Kasiski/重合指数） |
| 栅栏密码 | 字母数是合数 | CyberChef Magic |
| 培根密码 | 只含 a/b (A/B) 5 位一组 | CyberChef |
| 猪圈、键盘密码 | 图形/键盘位移 | 手动 |
| 摩斯电码 | `.` `-` | CyberChef |
| 埃特巴什码 | Atbash，字母镜像 | CyberChef |
| 仿射密码 | y = ax+b mod 26 | 暴力 a∈{1,3,5,7,9,11,15,17,19,21,23,25} |
| Playfair | 双字母分组 | 在线工具 |
| 序列密码/置换 | 字母频率正常但乱序 | 置换密码分析 |

## 4. 编码识别

| 特征 | 编码 |
|------|------|
| 末尾 `=`，字符集 A-Za-z0-9+/ | Base64 |
| 末尾 `=`，字符集 A-Z a-z 2-7 | Base32 |
| `0-9 A-F a-f` 偶数长度 | Hex |
| 只 `0` 和 `1`（8 位一组） | 二进制 |
| 只 0 和 1 与空格分隔 | 二进制/摩斯变体 |
| `\\u` 开头 | Unicode |
| `&#xx;` / `&#x` | HTML 实体 |
| `%xx` | URL 编码 |
| 由 `A-Z a-z 0-9 + /` 组成且无 `=`，长度较长 | Base64（尝试补 =） |
| 全大写字母+数字，常见混淆 | Base36 / Base58 / Base62 |
| `[]()!+` 组成 | JSFuck |
| `Ook. Ook?` / brainfuck `><+-.,[]` | Brainfuck 系 |
| 与佛论禅/新佛曰/熊曰 | 中文 fun 编码，用在线工具 |
| `不知所云的汉字` | 当铺密码（笔画数）等 |

综合工具：**CyberChef**（Magic 模块自动识别）、`scripts/decode.py`

## 5. 哈希与碰撞

```bash
hashid <hash>          # 识别哈希类型
hashcat -m <mode> hash.txt dict.txt
# 常见 mode: md5=0, sha1=100, sha256=1400, ntLM=1000, jwt=16500
```
- MD5 碰撞绕过（`==` 弱比较）：`0e` 开头哈希（magic hash，如 `240610708` 的 md5）
- 强比较碰撞：`md5() === md5()` 用 fastcoll 生成两个 PDF/图片
- 长度扩展攻击：MD5/SHA1 + `hash = H(key||msg)` 结构 → hashpumpy

## 6. 常见数学密码

- **离散对数**：小素数用 BSGS（大步小步）；p-1 平滑用 Pohlig-Hellman
- **椭圆曲线 ECC**：小曲线用 sage `discrete_log`；异常曲线（Smart's attack）；MOV 攻击
- **格密码（Lattice）**：识别特征——
  - 超递增序列 → 背包密码 → LLL 恢复
  - 线性方程组变量多方程少 → CVP/SVP
  - NTRU / LWE / SIS 结构
  - sage: `matrix(ZZ, ...).LLL()`
- **中国剩余定理 CRT**：多个同余方程合并
- **Rabin**：e=2 的 RSA，开平方模 p，4 个根逐一测试
- **Diffie-Hellman**：中间人/弱参数/给定部分值
- **AES**：
  - ECB 模式：分组重复模式泄露（penguin 图）
  - CBC：字节翻转攻击（改前一密文块操纵解密明文）、Padding Oracle
  - 密钥相关攻击：key 是时间戳/弱随机
  - 短密钥：直接爆破
- **OTP 复用**：两密文异或 → crib dragging（猜测明文片段滑动异或）

## 7. 随机数攻击

- `random.seed()` 已知 → 复现全部随机序列（Python `random.getrandbits` 可预测）
- MT19937 预测：需 624 个连续 32 位输出即可恢复状态（randcrack）
- 时间戳作种子：爆破附近时间
- nc 交互题目注意 `random.randint` 边界

## 8. 工具清单

| 工具 | 用途 |
|------|------|
| CyberChef | 编码/加密全家桶（网页版） |
| SageMath | 格/Coppersmith/ECC/大数运算 |
| yafu / msieve | 大数分解 |
| factordb.com | 查询 n 是否已被分解 |
| RsaCtfTool | 自动化 RSA 攻击 |
| pwntools | nc 交互 |
| xortool (GitHub) | XOR 密钥长度与恢复 |
| openssl | 证书分析 `openssl x509 -text -in cert.pem` |
