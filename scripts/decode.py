#!/usr/bin/env python3
"""
多合一编解码工具（纯标准库）

用法:
  python decode.py rot13 <text>
  python decode.py rot <n> <text>
  python decode.py b64 <text>            # 自动补齐 =
  python decode.py b32 <text>
  python decode.py b85 <text>
  python decode.py hex <text>
  python decode.py bin <text>            # 0/1 串（可含空格）
  python decode.py dec <text>            # 十进制串（空格分隔）转文本
  python decode.py url <text>
  python decode.py morse <text>
  python decode.py bacon <text>          # A/B 5位一组
  python decode.py tapcode <text>        # 敲击码 x,y
  python decode.py xor <hex> <key>       # hex 密文 xor hex/ascii key
  python decode.py freq <file>           # 字符频率分析（古典密码）
  python decode.py identify <text>       # 猜测编码类型
"""
import argparse
import base64
import collections
import re
import string
import sys

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "--..--": ",", ".-.-.-": ".", "..--..": "?",
    "-..-.": "/", "-....-": "-", "-.--.": "(", "-.--.-": ")",
}

TAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def dec_b64(text):
    text = text.strip().replace(" ", "")
    pad = (-len(text)) % 4
    return base64.b64decode(text + "=" * pad)


def dec_b32(text):
    text = text.strip().replace(" ", "").upper()
    pad = (-len(text)) % 8
    return base64.b32decode(text + "=" * pad)


def dec_b85(text):
    return base64.b85decode(text.strip())


def dec_hex(text):
    return bytes.fromhex(text.strip().replace(" ", ""))


def dec_bin(text):
    bits = re.sub(r"[^01]", "", text)
    if len(bits) % 8:
        bits = bits.zfill((len(bits) + 7) // 8 * 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def dec_dec(text):
    nums = text.replace(",", " ").split()
    return bytes(int(x) for x in nums)


def dec_url(text):
    import urllib.parse
    return urllib.parse.unquote(text).encode()


def dec_morse(text):
    parts = re.split(r"[ /]+", text.strip())
    out = []
    for p in parts:
        p = p.replace("_", "-")
        out.append(MORSE.get(p, "?"))
    return "".join(out).encode()


def dec_bacon(text):
    text = re.sub(r"[^ABab01]", "", text).upper().replace("0", "A").replace("1", "B")
    out = []
    for i in range(0, len(text) - 4, 5):
        grp = text[i:i + 5]
        val = int(grp.replace("A", "0").replace("B", "1"), 2)
        out.append(string.ascii_uppercase[val])
    return "".join(out).encode()


def dec_tapcode(text):
    out = []
    for pair in re.findall(r"(\d+)\s*,?\s*(\d+)", text):
        r, c = int(pair[0]), int(pair[1])
        idx = (r - 1) * 5 + (c - 1)
        if 0 <= idx < 26:
            out.append(TAP[idx])
    return "".join(out).encode()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def cmd_xor(args):
    data = bytes.fromhex(args.cipher.replace(" ", ""))
    key = args.key
    # 先尝试 hex，失败则按 ascii
    try:
        keyb = bytes.fromhex(key.replace(" ", ""))
        if not keyb:
            raise ValueError
    except ValueError:
        keyb = key.encode()
    result = xor_bytes(data, keyb)
    print("[hex] ", result.hex())
    print("[txt] ", safe_decode(result))


def safe_decode(b):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return repr(b)


def cmd_freq(args):
    with open(args.file, "rb") as f:
        content = f.read()
    try:
        text = content.decode("utf-8").upper()
    except UnicodeDecodeError:
        print("[-] 非 UTF-8 文本")
        return
    counter = collections.Counter(c for c in text if c.isalpha())
    total = sum(counter.values()) or 1
    print("字符频率（英文参考: E T A O I N S H R D L）:")
    for ch, cnt in counter.most_common(15):
        print(f"  {ch}: {cnt}  ({cnt/total:.1%})")
    eng = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    mapping = {ch: eng[i] for i, (ch, _) in enumerate(counter.most_common(26))}
    guess = "".join(mapping.get(c, c) for c in text)
    print("\n按频率替换猜测（仅参考）:")
    print(guess[:500])


def cmd_identify(args):
    text = args.text.strip()
    guesses = []
    t = text.replace(" ", "")
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        guesses.append(("hex", dec_hex(t)))
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t) % 4 == 1:
        guesses.append(("base64(需补齐)", dec_b64(t)))
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t):
        try:
            guesses.append(("base64", dec_b64(t)))
        except Exception:
            pass
    if re.fullmatch(r"[A-Z2-7]+={0,6}", t.upper()):
        try:
            guesses.append(("base32", dec_b32(t)))
        except Exception:
            pass
    if re.fullmatch(r"[01]+", t):
        guesses.append(("binary", dec_bin(t)))
    if re.fullmatch(r"[0-9]+(\s+[0-9]+)*", t):
        try:
            guesses.append(("decimal", dec_dec(t)))
        except Exception:
            pass
    if re.fullmatch(r"[.\-_/ ]+", text):
        guesses.append(("morse", dec_morse(text)))
    if re.fullmatch(r"[AB]+", t.upper()) and len(t) % 5 == 0:
        guesses.append(("bacon", dec_bacon(t)))
    if re.fullmatch(r"[<>+\-.\[\]]+", t):
        guesses.append(("brainfuck", "<用在线解释器运行 brainfuck>"))
    if "\\u" in text:
        guesses.append(("unicode-escape", text.encode().decode("unicode_escape").encode("latin-1")))
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        guesses.append(("url", dec_url(text)))
    if not guesses:
        print("[-] 未能识别，尝试 CyberChef Magic 模块")
        return
    for name, res in guesses:
        print(f"[{name}] {safe_decode(res) if isinstance(res, bytes) else res}")


def main():
    ap = argparse.ArgumentParser(description="多合一编解码工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("rot13"); p.add_argument("text")
    p = sub.add_parser("rot"); p.add_argument("n", type=int); p.add_argument("text")
    p = sub.add_parser("b64"); p.add_argument("text")
    p = sub.add_parser("b32"); p.add_argument("text")
    p = sub.add_parser("b85"); p.add_argument("text")
    p = sub.add_parser("hex"); p.add_argument("text")
    p = sub.add_parser("bin"); p.add_argument("text")
    p = sub.add_parser("dec"); p.add_argument("text")
    p = sub.add_parser("url"); p.add_argument("text")
    p = sub.add_parser("morse"); p.add_argument("text")
    p = sub.add_parser("bacon"); p.add_argument("text")
    p = sub.add_parser("tapcode"); p.add_argument("text")
    p = sub.add_parser("xor"); p.add_argument("cipher"); p.add_argument("key")
    p = sub.add_parser("freq"); p.add_argument("file")
    p = sub.add_parser("identify"); p.add_argument("text")

    args = ap.parse_args()
    try:
        if args.cmd == "rot13":
            res = args.text.translate(str.maketrans(
                string.ascii_lowercase + string.ascii_uppercase,
                string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
                string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))
            print(res)
        elif args.cmd == "rot":
            n = args.n % 26
            res = args.text.translate(str.maketrans(
                string.ascii_lowercase + string.ascii_uppercase,
                string.ascii_lowercase[n:] + string.ascii_lowercase[:n] +
                string.ascii_uppercase[n:] + string.ascii_uppercase[:n]))
            print(res)
        elif args.cmd == "xor":
            cmd_xor(args)
        elif args.cmd == "freq":
            cmd_freq(args)
        elif args.cmd == "identify":
            cmd_identify(args)
        else:
            fn = {
                "b64": dec_b64, "b32": dec_b32, "b85": dec_b85, "hex": dec_hex,
                "bin": dec_bin, "dec": dec_dec, "url": dec_url, "morse": dec_morse,
                "bacon": dec_bacon, "tapcode": dec_tapcode,
            }[args.cmd]
            print(safe_decode(fn(args.text)))
    except Exception as exc:
        print(f"[-] 解码失败: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
