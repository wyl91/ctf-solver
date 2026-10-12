#!/usr/bin/env python3
"""
RSA 常见攻击工具集（纯标准库实现，无需第三方依赖）

用法:
  python rsa_attacks.py small-e      --e 3 --c 12345 [--n 99999]
  python rsa_attacks.py wiener       --e e --n n
  python rsa_attacks.py fermat       --n n [--rounds 1000000]
  python rsa_attacks.py common       --n1 n1 --n2 n2 --e e --c1 c1 --c2 c2
  python rsa_attacks.py common-prime --n1 n1 --n2 n2 [--e e --c c]
  python rsa_attacks.py pollard-p1   --n n [--b1 100000]
  python rsa_attacks.py dp-leak      --n n --e e --dp dp --c c
  python rsa_attacks.py factordb     --n n          (需要网络, 尝试 factordb API)
  python rsa_attacks.py decrypt      --n n --e e --d d --c c   (已知私钥解密)
"""
import argparse
import json
import math
import sys
import urllib.request

# ---------- 基础工具 ----------

def iroot(x, k):
    """精确整数 k 次方根，返回 (root, exact)"""
    if x < 0:
        raise ValueError("负数无法开偶次方根")
    if x == 0:
        return 0, True
    r = int(round(x ** (1.0 / k)))
    for cand in (r - 2, r - 1, r, r + 1, r + 2):
        if cand >= 0 and cand ** k == x:
            return cand, True
    # 牛顿迭代兜底
    r = 1 << ((x.bit_length() + k - 1) // k)
    while True:
        nr = ((k - 1) * r + x // r ** (k - 1)) // k
        if nr >= r:
            break
        r = nr
    return r, r ** k == x


def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("模逆不存在 (gcd=%d)" % g)
    return x % m


def is_probable_prime(n, rounds=20):
    """Miller-Rabin"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    import random
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def report_int(name, val):
    print(f"[+] {name} = {val}")


def report_plain(m):
    print("[+] 明文(整数) =", m)
    b = long_to_bytes(m)
    print("[+] 明文(bytes) =", b)
    try:
        print("[+] 明文(utf-8) =", b.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    # 常见 flag 格式搜索
    import re
    mobj = re.search(rb"(flag|FLAG|ctf|CTF)\{[^}]{1,200}\}", b)
    if mobj:
        print("[+] FLAG ->", mobj.group(0).decode(errors="replace"))


def finish_with_d(n, e, d, c):
    m = pow(c, d, n)
    report_plain(m)


# ---------- 攻击实现 ----------

def attack_small_e(args):
    """小指数攻击: m^e < n 时直接开方"""
    e, c, n = args.e, args.c, args.n
    if e in (3, 5, 7, 17):
        r, exact = iroot(c, e)
        if exact:
            report_plain(r)
            return
        if n is None:
            print("[-] c 不是完全 e 次方数，需要提供 n 尝试 m^e = c + k*n")
            return
        # m^e = c + k*n
        for k in range(0, 1 << 20):
            root, exact = iroot(c + k * n, e)
            if exact:
                print(f"[+] k = {k}")
                report_plain(root)
                return
        print("[-] 100000 次内未找到，m 可能过大")
    else:
        print("[!] e 不算小指数，但仍尝试直接开方...")
        r, exact = iroot(c, e)
        if exact:
            report_plain(r)
        else:
            print("[-] 失败")


def attack_wiener(args):
    """Wiener 攻击: d < (1/3) n^(1/4) 时由连分数恢复 d"""
    e, n = args.e, args.n
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    # 收敛子
    convergents = [(0, 1), (1, 0)]
    for q in cf:
        k_prev, d_prev = convergents[-2]
        k_cur, d_cur = convergents[-1]
        convergents.append((q * k_cur + k_prev, q * d_cur + d_prev))
    for k, d in convergents[2:]:
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1  # p + q
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root, exact = iroot(disc, 2)
        if not exact:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n and is_probable_prime(p) and is_probable_prime(q):
            print("[+] Wiener 攻击成功!")
            report_int("d", d)
            report_int("p", p)
            report_int("q", q)
            if args.c:
                finish_with_d(n, e, d, args.c)
            return
    print("[-] Wiener 攻击失败，d 可能不够小 (可尝试 Boneh-Durfee, 需 sage)")


def attack_fermat(args):
    """Fermat 分解: p q 接近"""
    n, rounds = args.n, args.rounds
    a, _ = iroot(n, 2)
    a += 1
    for i in range(rounds):
        b2 = a * a - n
        b, exact = iroot(b2, 2)
        if exact and b > 0:
            p, q = a + b, a - b
            print(f"[+] Fermat 分解成功 (第 {i+1} 轮):")
            report_int("p", p)
            report_int("q", q)
            if args.e and args.c:
                d = modinv(args.e, (p - 1) * (q - 1))
                report_int("d", d)
                finish_with_d(n, args.e, d, args.c)
            return
        a += 1
    print(f"[-] {rounds} 轮内未分解，p q 差距较大")


def attack_common_prime(args):
    """两 n 共用素数: gcd 分解"""
    n1, n2 = args.n1, args.n2
    g = math.gcd(n1, n2)
    if g in (1, n1, n2):
        print("[-] gcd(n1,n2) =", g, "，无共享素数")
        return
    p = g
    q = n1 // p
    print("[+] 共享素数分解成功:")
    report_int("p", p)
    report_int("q", q)
    if args.e and args.c:
        d = modinv(args.e, (p - 1) * (q - 1))
        report_int("d", d)
        finish_with_d(n1, args.e, d, args.c)


def attack_common_modulus(args):
    """共模攻击: 同 n 同 m，不同 e"""
    n, e1, e2, c1, c2 = args.n, args.e1, args.e2, args.c1, args.c2
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        print(f"[-] gcd(e1,e2) = {g} != 1，不能直接共模攻击")
        if args.c1:
            r, exact = iroot(args.c1, g)
            if exact:
                print("[*] 尝试对 c1 开 g 次方成功:")
                report_plain(r)
        return
    if s1 < 0:
        c1 = modinv(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    print("[+] 共模攻击成功:")
    report_plain(m)


def attack_pollard_p1(args):
    """Pollard p-1: p-1 平滑"""
    n, b1 = args.n, args.b1
    if n % 2 == 0:
        print("[+] n 是偶数, 因子 2")
        return
    a = 2
    for j in range(2, b1):
        a = pow(a, j, n)
        if j % 5000 == 0:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                print(f"[+] Pollard p-1 成功 (j={j}):")
                report_int("p", g)
                report_int("q", n // g)
                if args.e and args.c:
                    p, q = g, n // g
                    d = modinv(args.e, (p - 1) * (q - 1))
                    finish_with_d(n, args.e, d, args.c)
                return
    g = math.gcd(a - 1, n)
    if 1 < g < n:
        print("[+] Pollard p-1 成功:")
        report_int("p", g)
        report_int("q", n // g)
    else:
        print(f"[-] B1={b1} 内失败，尝试增大 --b1")


def attack_dp_leak(args):
    """dp 泄露: 已知 n, e, dp 恢复 d"""
    n, e, dp, c = args.n, args.e, args.dp, args.c
    for x in range(2, e):
        if (dp * e - 1) % x == 0:
            phi = (dp * e - 1) // x
            pq_sum = n - phi + 1
            disc = pq_sum * pq_sum - 4 * n
            if disc < 0:
                continue
            root, exact = iroot(disc, 2)
            if not exact:
                continue
            p = (pq_sum + root) // 2
            q = (pq_sum - root) // 2
            if p * q == n:
                print(f"[+] dp 泄露攻击成功 (x={x}):")
                report_int("p", p)
                report_int("q", q)
                d = modinv(e, phi)
                report_int("d", d)
                if c:
                    finish_with_d(n, e, d, c)
                return
    print("[-] dp 泄露攻击失败")


def attack_factordb(args):
    """查询 factordb.com"""
    n = args.n
    try:
        url = f"http://factordb.com/api?query={n}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        status = data.get("status", "?")  # FF=已完全分解
        factors = data.get("factors", [])
        print(f"[*] factordb 状态: {status} (FF=完全分解, P=素数, C=合数未分解)")
        flat = []
        for f, exp in factors:
            flat.extend([int(f)] * exp)
        for f in flat:
            print("[+] 因子:", f)
        prod = 1
        for f in flat:
            prod *= f
        if prod == n and len(flat) >= 2:
            print("[+] 分解完整，可直接解密")
            if args.e and args.c and len(flat) == 2:
                p, q = flat[0], flat[1]
                phi = (p - 1) * (q - 1)
                d = modinv(args.e, phi)
                report_int("d", d)
                finish_with_d(n, args.e, d, args.c)
        else:
            print("[!] factordb 未完全分解")
    except Exception as exc:
        print("[-] 查询失败:", exc, "（可能无网络，尝试本地 fermat / pollard-p1）")


def attack_decrypt(args):
    """已知 d 直接解密"""
    finish_with_d(args.n, args.e, args.d, args.c)


# ---------- CLI ----------

def int_arg(s):
    return int(s, 0)  # 支持 0x 十六进制


def main():
    ap = argparse.ArgumentParser(description="RSA 常见攻击工具集")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--e", type=int_arg)
        p.add_argument("--n", type=int_arg)
        p.add_argument("--c", type=int_arg)

    p = sub.add_parser("small-e", help="小指数攻击 (e=3/5/7)")
    common(p)

    p = sub.add_parser("wiener", help="Wiener 攻击 (小 d)")
    common(p)

    p = sub.add_parser("fermat", help="Fermat 分解 (p q 接近)")
    common(p)
    p.add_argument("--rounds", type=int, default=1000000)

    p = sub.add_parser("common-prime", help="两 n 共享素数")
    p.add_argument("--n1", type=int_arg, required=True)
    p.add_argument("--n2", type=int_arg, required=True)
    p.add_argument("--e", type=int_arg)
    p.add_argument("--c", type=int_arg)

    p = sub.add_parser("common", help="共模攻击 (同 n 同 m 不同 e)")
    p.add_argument("--n", type=int_arg, required=True)
    p.add_argument("--e1", type=int_arg, required=True)
    p.add_argument("--e2", type=int_arg, required=True)
    p.add_argument("--c1", type=int_arg, required=True)
    p.add_argument("--c2", type=int_arg, required=True)

    p = sub.add_parser("pollard-p1", help="Pollard p-1 (p-1 平滑)")
    common(p)
    p.add_argument("--b1", type=int, default=100000)

    p = sub.add_parser("dp-leak", help="dp 泄露")
    p.add_argument("--n", type=int_arg, required=True)
    p.add_argument("--e", type=int_arg, required=True)
    p.add_argument("--dp", type=int_arg, required=True)
    p.add_argument("--c", type=int_arg)

    p = sub.add_parser("factordb", help="在线查询 factordb")
    common(p)

    p = sub.add_parser("decrypt", help="已知 d 解密")
    p.add_argument("--n", type=int_arg, required=True)
    p.add_argument("--e", type=int_arg, required=True)
    p.add_argument("--d", type=int_arg, required=True)
    p.add_argument("--c", type=int_arg, required=True)

    args = ap.parse_args()
    dispatch = {
        "small-e": attack_small_e,
        "wiener": attack_wiener,
        "fermat": attack_fermat,
        "common-prime": attack_common_prime,
        "common": attack_common_modulus,
        "pollard-p1": attack_pollard_p1,
        "dp-leak": attack_dp_leak,
        "factordb": attack_factordb,
        "decrypt": attack_decrypt,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
