# Misc 方向解题参考

## 1. 文件分析流程

```bash
file flag.xxx           # 识别真实文件类型
strings -n 6 flag.xxx | grep -i flag   # 提取可疑字符串
binwalk flag.xxx        # 检测嵌入文件
binwalk -e flag.xxx     # 自动提取
foremost flag.xxx -o out/   # 按文件头提取
xxd flag.xxx | head -50     # 十六进制查看（检查文件头）
```

**首选用 `scripts/file_triage.py <file>` 快速完成以上自动化分析。**

### 常见文件头（魔数）
| 文件类型 | 文件头 |
|---------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF`（结尾 `FF D9`） |
| GIF | `47 49 46 38` (GIF8) |
| ZIP | `50 4B 03 04` |
| RAR | `52 61 72 21` |
| 7z | `37 7A BC AF 27 1C` |
| PDF | `25 50 44 46` (%PDF) |
| ELF | `7F 45 4C 46` |
| BMP | `42 4D` |
| 文件头损坏 → 手工修复（如 PNG 尺寸字段、宽高被改） |

### PNG 宽高修复
IHDR 块偏移 16-24 字节为宽高（大端）。文件尺寸与宽高不符时，用 CRC 爆破正确宽高：
```python
import zlib, struct
data = open('flag.png','rb').read()
# 遍历 width/height 使 CRC 匹配
for w in range(1, 4096):
    for h in range(1, 4096):
        ihdr = data[12:16] + struct.pack('>II', w, h) + data[24:29]
        if zlib.crc32(ihdr) == struct.unpack('>I', data[29:33])[0]:
            print(w, h); break
```

## 2. 图片隐写

| 方法 | 命令/工具 |
|------|----------|
| PNG LSB | `zsteg flag.png`（必试） |
| 图片元数据 | `exiftool flag.jpg`（注释、作者字段藏 flag 很常见） |
| JPEG 追加数据 | `strings` / `binwalk`；`binwalk` 分离出压缩包 |
| steghide (JPEG) | `steghide extract -sf flag.jpg`（需要密码，密码常是题目提示） |
| stegseek | steghide 密码自动爆破 `stegseek flag.jpg rockyou.txt` |
| F5 (JPEG) | F5-steganography 工具 `java Extract` |
| jsteg / outguess | `jsteg reveal flag.jpg out.jpg`、`outguess -r flag.jpg out.txt` |
| 盲水印 | 频域盲水印工具（bwm.py），需要原图+水印图 |
| GIMP/PS | 通道分离、色阶调整、图层查看 |
| 宽高隐写 | 修改 PNG 宽高显示隐藏部分（爆破 CRC） |
| OurSecret/SilentEye | 界面工具，密码题干找 |
| 波形图 | 音频题目见下节 |

## 3. 音频隐写

```bash
# 频谱图查看（Audacity 打开 → 分析 → 频谱）常见 flag 直接写在频谱里
# 摩斯电码音频：Audacity 看波形长短
# SSTV 信号：用 MMSSTV/RX-SSTV 解码成图片
# DeepSound (wav/可加密)
# mp3stego: encode.exe -E hidden.txt -P pass song.mp3
# LSB: wavtool / python 读采样位
# 拨号音 DTMF: dtmf2num / 在线解码
# 最高位/最低位查看，倒放（Audacity 效果→反转）
```

## 4. 压缩包处理

| 场景 | 解法 |
|------|------|
| 伪加密 | ZIP 通用标志位（50 4B 后第 7-8 字节 `09 00` → `00 00`）；或用 ZipCenOp / 010 手改 |
| 暴力破解 | `fcrackzip -u -c a -l 1-10 flag.zip`；ARCHPR/Hashcat (-m 13600 zip) |
| 字典破解 | `fcrackzip -u -D -p dict.txt flag.zip` |
| CRC32 爆破 | 文件很小（<4字节）时按 CRC 爆破内容 |
| 明文攻击 | 已知部分明文 → `pkcrack`/ARCHPR 明文攻击 |
| 嵌套压缩 | 脚本循环解压（注意伪加密套娃） |
| 注释信息 | `unzip -z` / 7-zip 查看注释 |
| RAR | `rar2john` + `john` 破解 |

## 5. 流量分析（Wireshark / pcap）

```bash
# 常用过滤器
http                     # HTTP 流量
http.request.method == "POST"   # 上传数据
ftp-data                 # 传输的文件
tcp contains "flag"      # 内容搜索
frame contains "password"

# 提取文件: 文件 → 导出对象 → HTTP/FTP
# 追踪流: 右键 → Follow → TCP/HTTP Stream
# USB 键盘流量: usb.capdata / usbhid.data，字段数据按 HID 键码表还原
# USB 鼠标流量: 坐标还原画图
# ICMP 隐写: data 长度/内容异常
# tshark 命令行:
tshark -r flag.pcap -Y "http" -T fields -e http.request.uri
foremost flag.pcap -o out/    # 提取传输文件
```

## 6. 内存取证（Volatility）

```bash
volatility -f mem.raw imageinfo              # 识别系统版本
volatility -f mem.raw --profile=Win7SP1x64 pslist     # 进程列表
volatility -f mem.raw --profile=Win7SP1x64 cmdline    # 进程命令行
volatility -f mem.raw --profile=Win7SP1x64 filescan   # 文件
volatility -f mem.raw --profile=Win7SP1x64 dumpfiles -Q 0x... -D out/
volatility -f mem.raw --profile=Win7SP1x64 hashdump    # 密码哈希
volatility -f mem.raw --profile=Win7SP1x64 cmdline / notepad 插件
# Volatility3: python vol.py -f mem.raw windows.pslist
```
关注点：可疑进程、cmdline（truecrypt、cmd 命令）、notepad 文本、剪贴板、注册表（IE 历史、Run 键）、TrueCrypt 密钥

## 7. 磁盘取证

```bash
# TestDisk: 修复分区表/恢复删除文件
photorec disk.img       # 按文件类型恢复
fls disk.img            # 列出文件（含已删除）
icat disk.img <inode> > file   # 提取
mmls disk.img           # 查看分区
# VMDK/VHD 挂载查看
```

## 8. 其他常见题型

- **编码题**：见 `references/crypto.md` 编码识别表，用 `scripts/decode.py`
- **零宽字符**：文本看似为空/长度异常 → 用在线工具或 `vim -b` 查看零宽字符（ZWSP ZWNJ ZWJ）
- **社会主义核心价值观编码**：只含 12 个词组 → 在线工具
- **PDF**：`pdftotext`、对象流里的隐藏文本、`pdf-parser`、附件提取 `peepdf`
- **Excel/Word 隐写**：改后缀为 zip → 解压看 XML、隐藏工作表、白色文字、宏（olevba）
- **APK**：jadx 反编译、assets 内文件、`apktool d`
- **流量中的 SQL 注入还原**：URL decode 逐包拼接
- **NTFS 数据流**：`dir /r`（Windows）
- **雪花码/盲文/火星文**：中文编码类，找在线工具

## 9. 社工与 OSINT（少用但会遇到）

- 图片 EXIF GPS 定位（exiftool）
- 谷歌搜图/百度识图
- 题目描述中的人名/ID 搜索
