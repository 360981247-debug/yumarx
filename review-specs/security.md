# 企业 Python Web 服务安全代码评审规范（PR Server SPEC）

> **适用范围**：所有合并至主干分支的 PR diff，评审人必须逐项勾选并对每条发现标注严重级别、文件、行号、攻击路径、最小修复建议。
> **严重级别定义**：🔴 `Critical`（可直接获取服务器/数据库控制权限）→ 🟠 `High`（可越权访问/泄露敏感数据）→ 🟡 `Medium`（可绕过业务限制/信息泄漏辅助攻击）→ 🔵 `Low`（防御纵深缺失，单独利用困难）。

---

## 一、输入验证（Input Validation）

### 1.1 反序列化用户可控数据

| 项目 | 要求 |
|---|---|
| **检测点** | `pickle.loads()`、`yaml.load()`（不含 `SafeLoader`）、`marshal.loads()`、`shelve`、`eval()`、`exec()`、`ast.literal_eval()` 以外的 `eval` 族函数直接接收请求参数 |
| **严重级别** | 🔴 Critical |
| **攻击路径** | 攻击者构造恶意 pickle payload → 应用反序列化 → 触发 `__reduce__` → 任意代码执行（RCE） |
| **最小修复建议** | 禁止对外部输入使用 `pickle`/不安全 `yaml.load`；使用 `json.loads()` 或 `yaml.safe_load()` 替代；若必须反序列化 Python 对象，使用白名单类校验 + HMAC 签名验证。 |

### 1.2 文件上传未校验类型/内容

| 项目 | 要求 |
|---|---|
| **检测点** | `request.files` 或等价上传逻辑中：仅校验扩展名；未校验 magic bytes；未限制文件大小；保存路径使用用户输入拼接 |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者上传 `.py`/`.phtml`/`.htaccess` 等可执行后缀文件或伪装扩展名文件 → 存储至 Web 可访问目录 → 直接请求触发 RCE/覆盖关键文件 |
| **最小修复建议** | 使用 `python-magic` 校验 MIME magic bytes；白名单扩展名；存储时随机重命名（`uuid.uuid4().hex`）；存储目录禁止执行权限并置于 Web root 之外；通过 `MAX_CONTENT_LENGTH` 限制大小。 |

### 1.3 路径穿越（Path Traversal）

| 项目 | 要求 |
|---|---|
| **检测点** | 使用 `open()`、`os.path.join()`、`pathlib.Path` 拼接用户输入（文件名、目录名）而未做规范化校验；`send_file()` / `send_from_directory()` 直接传用户可控路径 |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者提交参数 `file=../../../../etc/passwd` → 未校验 → 读取服务器任意文件 → 泄露配置/密钥/源码 |
| **最小修复建议** | 对拼接后的路径做 `os.path.realpath()` 规范化，再校验其是否以 `BASE_DIR` 为前缀；优先使用 `send_from_directory(base_dir, safe_filename)`；文件名用白名单正则 `^[a-zA-Z0-9_.-]+$` 校验。 |

### 1.4 请求体/查询参数缺少 Schema 校验

| 项目 | 要求 |
|---|---|
| **检测点** | 视图函数/接口直接使用 `request.json`、`request.data`、`request.args`、`request.form` 字段而未经过 Pydantic/Marshmallow 等 Schema 校验，或校验后仍直接取字典外字段 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 攻击者注入额外字段（如 `is_admin=True`、`role="admin"`）→ 后端批量赋值（`**data`）→ 权限提升或数据污染 |
| **最小修复建议** | 所有外部输入必须使用 Pydantic `BaseModel`（`extra='forbid'`）或 Marshmallow Schema 校验后使用 `model.dict()` 输出；禁止 `MyModel(**request.dict())` 批量写入敏感字段。 |

### 1.5 正则表达式拒绝服务（ReDoS）

| 项目 | 要求 |
|---|---|
| **检测点** | 对用户输入使用含嵌套量词或回溯重的正则：如 `(a+)+`、`(a|a)+$`、`^(a+,?)+$` 等，并在请求同步路径上执行 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 攻击者提交长触发字符串 → 正则引擎指数级回溯 → CPU 占满 → 服务拒绝 |
| **最小修复建议** | 重写正则为线性无回溯形式（使用原子组/占有优先量词）；使用 `re2` 引擎替代 `re`；对输入长度设硬上限。 |

---

## 二、鉴权与越权（Authentication & Authorization / IDOR）

### 2.1 缺少认证保护的端点

| 项目 | 要求 |
|---|---|
| **检测点** | 视图/路由未加 `@login_required`、`Depends(get_current_user)` 或等价认证中间件；Django/Flask/FastAPI 路由中存在匿名可访问的写操作/管理操作接口 |
| **严重级别** | 🔴 Critical（若为管理/写接口）／🟠 High（若为敏感读接口） |
| **攻击路径** | 匿名攻击者直接请求 `/api/admin/delete_user`、`/api/v1/users/<id>/data` → 无认证拦截 → 执行操作或读取任意用户数据 |
| **最小修复建议** | 在路由层或全局中间件强制认证；敏感管理端点统一使用 RBAC 角色校验装饰器；默认拒绝策略（default-deny）白名单放行公开接口。 |

### 2.2 水平越权（IDOR / BOLA）

| 项目 | 要求 |
|---|---|
| **检测点** | 接口通过 `id`/`user_id`/`order_id` 等路径或查询参数访问资源，但未校验资源归属（如查询时仅 `id=xxx` 而未加 `owner_id=current_user.id` 条件）；使用 `get_object_or_404(Model, pk=id)` 后未校验 `obj.user_id == current_user.id` |
| **严重级别** | 🟠 High |
| **攻击路径** | 用户 A 登录 → 遍历 `/api/users/1001/orders`、`/api/orders/2001` 中 id → 直接读取/修改其他用户订单、账单、个人信息 |
| **最小修复建议** | 所有按 ID 查询必须附加租户/所属用户过滤条件：`Order.objects.filter(id=oid, user_id=current_user.id)`；Django 层使用 `django-guardian`/自定义权限校验；单元测试必须覆盖跨用户访问用例。 |

### 2.3 垂直越权（权限提升到管理员）

| 项目 | 要求 |
|---|---|
| **检测点** | 管理员接口仅用"角色字段"前端隐藏/菜单隐藏而无后端校验；`is_staff`/`is_superuser`/`role` 字段可被普通用户通过 PUT/PATCH 更新；中间件仅校验登录不校验角色 |
| **严重级别** | 🔴 Critical |
| **攻击路径** | 普通用户注册 → 在请求体中添加 `"role": "admin"`、`"is_superuser": true` → 后端批量更新 → 成为管理员 |
| **最小修复建议** | 使用角色白名单装饰器 `@require_role("admin")` 校验；序列化器（DRF Serializer/Pydantic）将 `role`/`is_superuser` 字段设为 `read_only=True`；ORM `update_fields` 显式列出可写字段。 |

### 2.4 JWT / Session 安全缺陷

| 项目 | 要求 |
|---|---|
| **检测点** | JWT `alg: none` 未禁用；签名密钥硬编码或弱密钥；未校验 `exp`/`iss`/`aud`；Session Cookie 未设置 `HttpOnly`/`Secure`/`SameSite=Strict|Lax`；Session ID 可预测或未在登出/密码修改时轮换 |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者伪造 alg=none 令牌 → 绕过签名校验 → 冒充任意用户；或 XSS 读取未设 HttpOnly 的 session cookie → 劫持会话 |
| **最小修复建议** | 使用 `PyJWT`/`python-jose` 解码时显式指定 `algorithms=["HS256"]` 并拒绝 `none`；Cookie 设置 `httponly=True, secure=True, samesite="Lax"`；登录/登出/密码变更后调用 `request.session.cycle_key()` 轮换 session。 |

---

## 三、注入（Injection）

### 3.1 SQL 注入

| 项目 | 要求 |
|---|---|
| **检测点** | 使用字符串拼接/f-string 构造 SQL：`f"SELECT * FROM users WHERE id = {user_id}"`；使用 `RawSQL()`/`cursor.execute(f"...")` 直接拼接参数；ORM `extra()`/`raw()` 中嵌入未参数化变量 |
| **严重级别** | 🔴 Critical |
| **攻击路径** | 攻击者传入 `id=1 OR 1=1 --` → SQL 拼接 → 返回全表数据；或堆叠查询写入 webshell/提权 |
| **最小修复建议** | 一律使用参数化查询：`cursor.execute("SELECT ... WHERE id = %s", [user_id])`；ORM 查询使用 `User.objects.filter(id=user_id)` 或 `.raw("... WHERE id = %s", [user_id])`；禁止 `extra()` 中使用字符串插值。 |

### 3.2 命令注入（OS Command Injection）

| 项目 | 要求 |
|---|---|
| **检测点** | `os.system()`、`subprocess.run(cmd, shell=True)`、`subprocess.Popen(shell=True)`、`commands.getoutput()` 中包含用户可控数据；即使无 `shell=True` 但将字符串拆分列表时未做白名单校验 |
| **严重级别** | 🔴 Critical |
| **攻击路径** | 用户传入 `filename=a.jpg; rm -rf /` → `shell=True` 拼接执行 → 服务器任意命令执行 |
| **最小修复建议** | 禁止 `shell=True`；使用参数列表形式 `subprocess.run(["convert", safe_path, out_path], shell=False, check=True, timeout=...)`；命令路径使用绝对路径；外部输入作为文件参数时必须经路径穿越校验；若需限制命令集合，使用白名单字典映射。 |

### 3.3 模板注入（SSTI / XSS）

| 项目 | 要求 |
|---|---|
| **检测点** | Jinja2/Flask/Django 模板中使用 `|safe`、`Markup()`、`{{ var|safe }}` 渲染用户输入；Flask 使用 `render_template_string(user_input)`；Django `mark_safe()` 包裹外部数据；DRF/接口直接返回未转义 HTML |
| **严重级别** | 🟠 High（XSS）/ 🔴 Critical（SSTI 可 RCE） |
| **攻击路径** | 攻击者在昵称/评论字段注入 `{{ config }}`、`{{ ''.__class__.__mro__[1].__subclasses__() }}` → `render_template_string` 渲染 → SSTI RCE；或 `<script>...</script>` 触发存储型 XSS |
| **最小修复建议** | 禁止 `render_template_string` 接收用户内容；默认使用 Jinja2/Django 自动转义（不使用 `|safe`）；必须输出 HTML 时使用 `bleach.clean()` 白名单标签清洗；API 返回 JSON 而非拼接 HTML。 |

### 3.4 NoSQL / ORM 注入

| 项目 | 要求 |
|---|---|
| **检测点** | MongoDB/Elasticsearch 查询直接传入用户字典：`col.find(request.json)`；使用 `$where`、`$regex` 运算符接收用户输入而未转义；Django ORM `__regex` 未转义特殊字符 |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者在登录接口传入 `{"username": {"$ne": null}, "password": {"$ne": null}}` → MongoDB 返回第一条用户 → 绕过登录 |
| **最小修复建议** | 显式构造查询字典并只接收白名单字段；使用 Pydantic/Schema 校验字段类型；对正则字段调用 `re.escape()`。 |

### 3.5 LDAP / XML / XXE 注入

| 项目 | 要求 |
|---|---|
| **检测点** | `python-ldap` 查询使用 f-string 拼接 DN/FILTER；`lxml`/`xml.etree` 解析外部 XML 未禁用外部实体；`defusedxml` 未使用 |
| **严重级别** | 🟠 High |
| **攻击路径** | XML 中声明 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` → 解析器展开 → 读取本地文件；LDAP 过滤注入绕过认证 |
| **最小修复建议** | 使用 `defusedxml` 替代标准 `xml` 库；LDAP 查询使用 `ldap.filter.escape_filter_chars()` 转义用户输入并使用参数化 API。 |

---

## 四、敏感信息泄露（Sensitive Data Exposure）

### 4.1 硬编码密钥/凭据

| 项目 | 要求 |
|---|---|
| **检测点** | 源码中出现明文 `SECRET_KEY`、`API_KEY`、`DB_PASSWORD`、`AWS_ACCESS_KEY_ID`、`GITHUB_TOKEN`、私钥块（`-----BEGIN RSA PRIVATE KEY-----`）；`settings.py` 中默认密钥提交到仓库 |
| **严重级别** | 🔴 Critical |
| **攻击路径** | 攻击者阅读公开/内部仓库源码 → 获取密钥 → 访问数据库/云资源/第三方 API → 数据泄漏/资源盗刷 |
| **最小修复建议** | 一律从环境变量读取：`os.getenv("SECRET_KEY")`，启动时校验存在性；使用 `.env`（加入 `.gitignore`）+ `.env.example`（占位符）；历史泄漏密钥立即轮换；启用 Git 历史 secret scanning（如 `gitleaks`）。 |

### 4.2 日志/响应/异常栈泄漏敏感数据

| 项目 | 要求 |
|---|---|
| **检测点** | `logger.info(f"user={user}, password={password}")` 输出密码/Token/身份证/银行卡；DEBUG=True 下生产环境返回详细 traceback；异常消息包含 SQL 语句、文件路径、内部 IP |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者触发异常（如畸形参数）→ 500 页面返回完整栈和 SQL → 获取表结构/密钥片段/内部网络拓扑 |
| **最小修复建议** | 生产环境 `DEBUG=False`，配置自定义异常处理器返回通用错误信息；日志使用结构化过滤器遮蔽敏感字段（如 `filter: hide_pii` 对 `password/token/secret/authorization` 字段 `***` 遮蔽）；禁止在 INFO 级别打印请求体原文。 |

### 4.3 不安全的加密/哈希算法

| 项目 | 要求 |
|---|---|
| **检测点** | 密码存储使用 MD5/SHA1/普通 SHA256（无盐）；使用 ECB 模式；硬编码 IV；使用 `cryptography` 但密钥派生使用无 KDF 的方式；JWT 使用 `HS256` 但密钥长度 < 256 位 |
| **严重级别** | 🟠 High |
| **攻击路径** | 数据库被拖库 → MD5/SHA1 彩虹表秒破 → 获取明文密码 → 横向撞库 |
| **最小修复建议** | 密码哈希使用 `bcrypt`（rounds ≥ 12）或 `argon2-cffi`；对称加密使用 AES-256-GCM，随机 nonce；密钥派生使用 `PBKDF2HMAC`/`scrypt`。 |

### 4.4 不安全的 TLS / 传输配置

| 项目 | 要求 |
|---|---|
| **检测点** | 对外调用使用 `verify=False`；内部服务 HTTP 明文；客户端 `requests.get(url, verify=False)`；使用过时协议（TLS<1.2） |
| **严重级别** | 🟠 High |
| **攻击路径** | 中间人攻击截获请求 → 获取 OAuth token/用户数据/API 密钥 |
| **最小修复建议** | 删除所有 `verify=False`，使用系统 CA 或自签 CA 包；客户端强制执行 TLS1.2+；生产环境强制 HTTPS 跳转（HSTS）。 |

---

## 五、SSRF（服务端请求伪造）

### 5.1 用户可控 URL 被后端请求

| 项目 | 要求 |
|---|---|
| **检测点** | `requests.get(user_url)`、`urllib.request.urlopen(url)`、`httpx.get(url)`、`aiohttp` 等 HTTP 客户端直接请求用户提供的 URL；Webhook/头像下载/URL 预览/oEmbed 等功能点；云环境中元数据地址（`169.254.169.254`）未阻断 |
| **严重级别** | 🔴 Critical（云环境）/ 🟠 High（传统环境） |
| **攻击路径** | 攻击者传入 `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → 后端发起请求 → 获取云实例 IAM 临时凭证 → 接管云账号；或探测内网 `http://10.0.0.1:6379/` → 访问 Redis/数据库等内网服务 |
| **最小修复建议** | **(1) 协议白名单**：仅允许 `http`/`https`；**(2) DNS 解析后 IP 校验**：解析 host 后拒绝私有/保留 IP（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`、`169.254.0.0/16`、`::1`、`fc00::/7` 等）；**(3) 禁止重定向跟随**或校验重定向目标；**(4) 出口隔离**：将外部请求功能放在独立网络命名空间/安全组，禁止访问元数据和内网；**(5) 响应大小/超时限制**。 |

### 5.2 重定向开放（Open Redirect）

| 项目 | 要求 |
|---|---|
| **检测点** | `return redirect(request.args.get("next"))`、`return HttpResponseRedirect(next_url)` 未校验目标 host |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 钓鱼链接 `/login?next=https://evil.com` → 用户登录后跳转钓鱼站 → 窃取凭据 |
| **最小修复建议** | 校验 URL netloc 必须在白名单域内；或仅允许相对路径（以 `/` 开头且不以 `//` 开头）。 |

---

## 六、外部调用风险（Outbound Calls / Third-Party Integration）

### 6.1 未设置超时/重试/大小限制导致拒绝服务

| 项目 | 要求 |
|---|---|
| **检测点** | `requests.get(url)` 未传 `timeout`；HTTP 客户端未设 `max_redirects`；下载文件时 `response.content` 全量读入内存而未流式限制大小；未配置连接池导致端口耗尽 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 被调用服务缓慢响应/不响应 → 工作线程/协程堆积 → 服务雪崩；或响应巨大（10GB）导致内存耗尽 OOM |
| **最小修复建议** | 所有出站请求设置 `timeout=(connect_timeout, read_timeout)`（建议 ≤ 5s/30s）；下载时流式读取并设置最大字节数（如 `MAX_RESPONSE_SIZE = 10 * 1024 * 1024` 超限立即断开）；使用连接池复用，配置 `pool_connections`/`pool_maxsize`。 |

### 6.2 未校验外部响应/状态码

| 项目 | 要求 |
|---|---|
| **检测点** | 调用支付/短信/验证码等接口未校验 HTTP 状态码和业务返回码直接认为成功；Webhook 回调未验签就执行业务逻辑（订单状态变更、退款等） |
| **严重级别** | 🟠 High |
| **攻击路径** | 攻击者伪造回调请求 → 无签名校验 → 标记订单已支付/触发退款 → 资金损失 |
| **最小修复建议** | 严格校验 `status_code == 200` 且业务码匹配；Webhook 必须验证 HMAC 签名（如 Stripe-Signature、X-Signature），时间戳防重放；回调处理幂等。 |

### 6.3 错误/异常信息将内部第三方细节透传

| 项目 | 要求 |
|---|---|
| **检测点** | 将第三方 API 返回原文（含内部 URL、API Key、trace id）直接返回给前端或写入错误日志被低权限用户访问 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 攻击者主动触发外部调用失败 → 错误信息泄露内部服务域名/key → 作为后续攻击起点 |
| **最小修复建议** | 对外统一返回 `{"code": "upstream_error", "message": "service unavailable"}`；内部日志只记录 request_id 和脱敏错误信息。 |

### 6.4 反序列化外部服务响应

| 项目 | 要求 |
|---|---|
| **检测点** | 对外部服务返回的 XML/JSON/YAML/Pickle 直接解析且未限制大小/深度；使用 `xmltodict.parse`/`eval`/`pickle` 处理第三方响应 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 第三方被攻陷或 DNS 劫持 → 返回 XXE/恶意 pickle payload → 触发本地 XXE/RCE |
| **最小修复建议** | 同样适用 3.5 节规则：使用 `defusedxml`；禁止反序列化外部 pickle；JSON 解析设置深度/键数上限。 |

---

## 七、供应链风险（Supply Chain）

### 7.1 依赖包存在已知漏洞

| 项目 | 要求 |
|---|---|
| **检测点** | `requirements.txt`/`pyproject.toml`/`Pipfile.lock`/`poetry.lock` 中存在 CVE（使用 `safety check`/`pip-audit`/Dependabot 扫描命中）；使用已废弃/无人维护包（如 `pycrypto`、`random` 做安全用途、`itsdangerous<2.0` 老版本） |
| **严重级别** | 视 CVE 评分：🔴 Critical（RCE、鉴权绕过）/ 🟠 High（其他）/ 🟡 Medium（低危） |
| **攻击路径** | 攻击者利用已知 CVE（如 `jinja2<2.11.3` 沙箱逃逸、`pyyaml<5.4` 任意代码、`urllib3<1.26.5` SSRF 等）→ 在特定调用路径触发 → 代码执行/信息泄露 |
| **最小修复建议** | 升级到官方修复版本；无修复则寻找替代包或添加缓解措施（如 WAF 规则、输入限制）；CI 中强制运行 `pip-audit -r requirements.txt` 阻断高危依赖合并。 |

### 7.2 恶意包/包名混淆（Typosquatting）

| 项目 | 要求 |
|---|---|
| **检测点** | 新增依赖包名与知名包近似（如 `djanga`、`requets`、`python-jose` 与 `jose`、`crypto` 与 `pycryptodome`）；从非官方 PyPI 源安装；直接从 git URL/HTTP URL 安装 |
| **严重级别** | 🟠 High |
| **攻击路径** | 开发者误装恶意包 → `setup.py` 安装阶段执行恶意代码 → 窃取本地凭据/植入后门 |
| **最小修复建议** | 新增依赖必须经安全团队审核；只使用官方 PyPI 并固定哈希（`pip --require-hashes`）；锁文件必须提交；禁止在 `requirements.txt` 中使用 `git+https://` 分支依赖（必须 tag + hash）。 |

### 7.3 安装脚本/`setup.py` 执行任意代码

| 项目 | 要求 |
|---|---|
| **检测点** | `setup.py`/`setup.cfg`/`pyproject.toml` 中包含 `__import__('os').system(...)`、post-install hooks、网络下载；CI/CD 构建阶段执行未审查的脚本（如 `make install` 触发 curl | sh） |
| **严重级别** | 🟠 High |
| **攻击路径** | 包作者或被篡改发布包含恶意 `setup.py` → `pip install` 即执行 → 开发者机器/CI 环境被入侵 |
| **最小修复建议** | 审查新增依赖的构建脚本；CI 构建在沙箱/无网络环境中执行；优先 wheel 分发而非 sdist。 |

### 7.4 开发依赖（dev deps）被打包进运行时镜像

| 项目 | 要求 |
|---|---|
| **检测点** | Dockerfile 中 `pip install -r requirements.txt -r dev-requirements.txt` 后直接作为运行镜像；测试框架（`pytest`、`ipython`）、代码质量工具在生产镜像中存在 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 攻击者进入容器 → 利用 dev 工具（debug shell、pytest 插件）进一步利用漏洞；镜像体积膨胀引入更多 CVE 面 |
| **最小修复建议** | 使用多阶段构建：builder 阶段安装全部依赖，运行阶段只安装 `requirements.txt`；或使用 `pip install --no-dev`；生产镜像使用 `distroless`/`slim` 基础镜像。 |

### 7.5 不安全的包源/PyPI 镜像配置

| 项目 | 要求 |
|---|---|
| **检测点** | `pip.conf`/`PIP_INDEX_URL` 设为 HTTP 镜像或不受信的第三方源；未启用 TLS 校验；企业内部 PyPI 未做包签名 |
| **严重级别** | 🟡 Medium |
| **攻击路径** | 中间人替换包内容 → 植入后门 → 服务器被入侵 |
| **最小修复建议** | 使用官方 PyPI 或企业内部 HTTPS + 包签名镜像源；`pip` 配置 `trusted-host` 仅在必要时使用，生产环境关闭。 |

---

## 八、评审输出格式（强制）

每条发现必须严格按以下模板输出，不得缺项：

```markdown
### [发现编号] 简短标题

- **严重级别**：🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
- **分类**：输入验证 / 鉴权越权 / 注入 / 敏感信息 / SSRF / 外部调用 / 供应链
- **文件**：`path/to/file.py`
- **行号**：L<start>[-L<end>]
- **攻击路径**：
  1. 攻击者在<入口>传入<恶意输入>；
  2. <代码中存在的缺陷处理路径>；
  3. 最终导致<RCE/越权/数据泄露/DoS 等具体影响>。
- **最小修复建议**：
  > 给出可直接替换的最小代码片段或配置变更，控制在 5 行以内；不得引入与本问题无关的重构。
- **验证用例（建议）**：给出一条 curl/测试代码，证明修复前后差异。
```

---

## 九、评审门禁规则

1. **任何 🔴 Critical 发现**：PR 直接 Block，必须修复后重新评审。
2. **任何 🟠 High 发现**：PR Block；如属业务确认可接受风险，须由安全负责人在 PR 评论中明确签字豁免（带豁免编号与过期时间）。
3. **🟡 Medium 发现**：原则上本次 PR 修复；经安全团队同意可创建已知 Issue 跟踪，下个迭代前解决。
4. **🔵 Low 发现**：记录为 Tech Debt，不阻塞合并。
5. **评审人义务**：每条发现必须复现或给出可复现路径；不得使用"建议优化"等模糊表述，必须明确"可利用/不可利用"判定。
6. **CI 强制项**：`bandit -r .`、`pip-audit`、`semgrep --config auto` 必须在 CI 流水线中通过，结果作为评审辅助依据但不替代人工评审。

---

## 十、快速检查清单（评审 PR 时必过）

- [ ] 所有外部输入是否经过 Schema 校验且无批量赋值敏感字段？
- [ ] 每个写接口/敏感读接口是否做了认证 + 归属/角色校验？
- [ ] 所有 SQL/命令/模板/查询是否参数化或经过白名单/转义？
- [ ] 是否存在硬编码密钥？DEBUG 是否关闭？异常是否通用化？
- [ ] 后端是否对用户传入 URL 做协议/DNS/IP 多重校验？
- [ ] 所有出站调用是否设超时、大小限制、验签？
- [ ] 新增依赖是否经审核？是否带锁文件？是否有已知 CVE？
- [ ] 日志/响应是否可能泄露密码、Token、内部地址？
