#!/usr/bin/env python3
"""
Misc 文件初步分析工具（纯标准库，模拟 file + strings + binwalk 检查）

用法: python file_triage.py <文件路径>
"""
import os
import re
import sys

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"GIF87a", "GIF 图片"),
    (b"GIF89a", "GIF 图片"),
    (b"BM", "BMP 图片"),
    (b"PK\x03\x04", "ZIP 压缩包"),
    (b"PK\x05\x06", "空 ZIP"),
    (b"Rar!\x1a\x07", "RAR 压缩包"),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩包"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"%PDF", "PDF 文档"),
    (b"\x7fELF", "ELF 可执行文件"),
    (b"MZ", "Windows PE (EXE)"),
    (b"\xca\xfe\xba\xbe", "Java CLASS / Mach-O"),
    (b"\x1bLua", "Lua 字节码"),
    (b"OggS", "OGG 音频"),
    (b"ID3", "MP3 音频"),
    (b"RIFF", "WAV/AVI (RIFF 容器)"),
    (b"fLaC", "FLAC 音频"),
    (b"-----BEGIN", "PEM 文本(密钥/证书)"),
]

# 常见嵌入文件在压缩/打包数据中的特征
EMBED_SIGS = [
    (b"PK\x03\x04", "ZIP 数据"),
    (b"\x89PNG", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"Rar!", "RAR 数据"),
    (b"7z\xbc\xaf", "7z 数据"),
    (b"%PDF", "PDF 数据"),
    (b"\x7fELF", "ELF 文件"),
    (b"flag{", "flag 明文!"),
    (b"FLAG{", "flag 明文!"),
    (b"ctf{", "flag 明文!"),
    (b"CTF{", "flag 明文!"),
]

FLAG_RE = re.compile(rb"(flag|FLAG|ctf|CTF|key|KEY)\{[^}\s]{1,200}\}")
BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")


def hexdump(data, start, length, max_lines=4):
    lines = []
    for off in range(start, min(start + length, len(data)), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:08x}  {hexs:<47}  {asc}")
        if len(lines) >= max_lines:
            break
    return "\n".join(lines)


def main(path):
    if not os.path.isfile(path):
        print(f"[-] 文件不存在: {path}")
        sys.exit(1)
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read()

    print(f"=== 文件: {path}  大小: {size} 字节 ===\n")

    # 1. 魔数识别
    print("[文件类型]")
    detected = None
    for magic, name in MAGIC:
        if data.startswith(magic):
            detected = name
            print(f"  {name} (头部匹配: {magic[:8]!r})")
            break
    if not detected:
        print("  未知类型! 前 64 字节:")
        print(hexdump(data, 0, 64))
        print("  -> 文件头可能被破坏/篡改，或为纯文本")
        try:
            txt = data[:200].decode("utf-8")
            print("  作为文本预览:", txt[:100].replace("\n", "\\n"))
        except UnicodeDecodeError:
            pass

    # 2. 嵌入数据检测 (跳过自身头部)
    print("\n[嵌入数据检测] (binwalk 类似功能)")
    found = False
    for sig, name in EMBED_SIGS:
        positions = []
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            positions.append(idx)
            start = idx + 1
            if len(positions) > 10:
                break
        for pos in positions:
            if detected and pos == 0:
                continue  # 自身头部
            found = True
            print(f"  偏移 0x{pos:x} ({pos}): {name}")
    if not found:
        print("  未发现嵌入文件特征")

    # 3. flag 模式搜索
    print("\n[flag 模式搜索]")
    flags = FLAG_RE.findall(data) if hasattr(FLAG_RE, "findall") else []
    matches = FLAG_RE.finditer(data)
    got = False
    for m in matches:
        got = True
        print(f"  偏移 {m.start()}: {m.group(0).decode(errors='replace')}")
    if not got:
        print("  未直接发现 flag{...} 模式")

    # 4. 可打印字符串
    print("\n[可疑字符串] (含关键词, 前 40 条)")
    strings = re.findall(rb"[\x20-\x7e]{6,}", data)
    keywords = (b"flag", b"key", b"pass", b"ctf", b"user", b"admin",
                b"http", b".php", b"secret", b"hint",
                "提示".encode("utf-8"), "密码".encode("utf-8"))
    hits = []
    for s in strings:
        low = s.lower()
        if any(k in low for k in keywords):
            hits.append(s)
    for s in hits[:40]:
        print("  ", s.decode(errors="replace"))
    if not hits:
        print("  无关键词命中；普通字符串前 10 条:")
        for s in strings[:10]:
            print("  ", s.decode(errors="replace"))

    # 5. Base64 样长字符串
    print("\n[疑似 Base64 长串] (前 5 条)")
    cnt = 0
    for m in BASE64_RE.finditer(data):
        print(f"  偏移 {m.start()}: {m.group(0)[:80].decode()}...")
        cnt += 1
        if cnt >= 5:
            break
    if cnt == 0:
        print("  无")

    # 6. PNG 专项: 宽高检查
    if data.startswith(b"\x89PNG"):
        import struct, zlib
        print("\n[PNG 结构]")
        if len(data) > 33 and data[12:16] == b"IHDR":
            w, h = struct.unpack(">II", data[16:24])
            crc_stored = struct.unpack(">I", data[29:33])[0]
            crc_calc = zlib.crc32(data[12:29])
            print(f"  宽x高 = {w} x {h}, IHDR CRC {'正确' if crc_stored == crc_calc else '不匹配(宽高被改,需爆破)'}")
        # 列出 chunk
        off = 8
        while off < len(data) - 8:
            length = struct.unpack(">I", data[off:off + 4])[0]
            ctype = data[off + 4:off + 8]
            print(f"  chunk {ctype.decode(errors='replace')} @0x{off:x} len={length}")
            if ctype == b"IEND":
                extra = len(data) - (off + 12)
                if extra > 0:
                    print(f"  [!] IEND 后仍有 {extra} 字节附加数据!")
                break
            off += 12 + length

    # 7. ZIP 伪加密检查
    if data.startswith(b"PK"):
        print("\n[ZIP 检查]")
        idx = 0
        encrypted = False
        while True:
            idx = data.find(b"PK\x01\x02", idx)
            if idx < 0:
                break
            flag_bits = data[idx + 8:idx + 10]
            if flag_bits == b"\x09\x00" or (flag_bits[0] & 1):
                encrypted = True
                print(f"  [!] 中央目录 @0x{idx:x} 标记加密 (伪加密嫌疑: 标志位 09 00)")
            idx += 4
        if not encrypted:
            print("  未检测到加密标志")

    print("\n=== 分析完成 ===")
    print("提示: 若有嵌入数据, 用 binwalk -e / foremost 提取; 图片再跑 zsteg/exiftool/steghide")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
