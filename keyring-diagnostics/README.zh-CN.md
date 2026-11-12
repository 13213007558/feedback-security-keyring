# keyring 后端选择诊断入口

同一个服务在「交互 shell 启动」与「进程管理器（launchd/systemd/容器入口点）启动」
下拿到不同 keyring 后端，根因是 `keyring` 的选择链对三类输入按固定优先级短路：

```
keyring.core._detect_backend:
    load_env()            # 1. 环境变量 PYTHON_KEYRING_BACKEND
  or load_config()         # 2. 配置文件 keyringrc.cfg（可含 keyring-path）
  or max(viable 插件,      # 3. entry point 组 keyring.backends 中 priority 最高者
         default=fail.Keyring())
```

对应源码：`keyring/core.py:96`（`_detect_backend`）、`keyring/core.py:150`
（`load_env`）、`keyring/core.py:168`（`load_config`）、`keyring/backend.py:246`
（`get_all_keyring` / entry point 发现）。

## 文件

- `keyring_diagnose.py` — 诊断入口。逐层重放选择链、列 entry point 与可写性、
  输出最终后端的安全能力；支持 `--json`。环境变量只打印**变量名**，值一律
  显示 `<set, redacted>`。
- `make_fake_plugins.py` — 在临时目录生成两个独立的假 entry point 发行包：
  `fake_vault`（模拟加密 OS vault，缺属性时构造期硬失败）与 `fake_legacy`
  （模拟明文文件后端）。
- `run_scenarios.sh` — 用临时 HOME + `env -i` 构造两套最小启动环境并对比。
- `verify_pin_and_failures.sh` — 验证最小固定配置生效，以及错误配置显式失败、
  不会静默回退（13 项断言）。

## 复现

```sh
zsh keyring-diagnostics/run_scenarios.sh          # 两套环境 + 对比汇总
zsh keyring-diagnostics/verify_pin_and_failures.sh
python keyring-diagnostics/keyring_diagnose.py    # 对当前环境直接诊断
python keyring-diagnostics/keyring_diagnose.py --json
```

所有产物写在 `$TMPDIR` 下的一次性目录，脚本退出即删除；子进程用 `env -i` 启动，
仅显式传入 `HOME`、`PATH`、`PYTHONPATH` 与 keyring 相关变量，因此输出与本机
shell 的其它变量无关、可重复。

## 两套环境的差异（实测）

| 维度 | 交互启动 | 进程管理器启动 |
| --- | --- | --- |
| 命中阶段 | `1_env`（环境变量短路） | `2_config`（配置文件短路） |
| 选择来源 | `PYTHON_KEYRING_BACKEND=fake_vault.VaultKeyring` | `keyringrc.cfg` 的 `default-keyring` |
| 插件属性 | `KEYRING_PROPERTY_VAULT_PIN` 等注入实例 | 无环境属性 |
| 最终后端 | `fake_vault.VaultKeyring` | `fake_legacy.LegacyFileKeyring` |
| 静态加密 | 是 | 否（明文） |
| 重启保留 | 是 | 是 |
| 若移除前两层的自动结果 | `chainer.ChainerBackend`（priority 10，组合委托） | 同左 |

进程管理器场景还演示了 `keyring-path`：它把可写目录插入 `sys.path[0]`，
诊断输出明确标注 `code-execution surface`——任何能写该目录的人都能投放
后端模块，等价于代码执行面。

## 哪些输入来自可写位置

诊断第 8 节逐项标注，本仓库环境下全部命中 `WRITABLE`：

- 进程环境（`PYTHON_KEYRING_BACKEND`、`KEYRING_PROPERTY_*`）——能拉起进程
  的任何组件（shell profile、service unit、容器入口点）都可改写。
- 配置根与 `keyringrc.cfg`：
  - Linux/其它 Unix：`$XDG_CONFIG_HOME/python_keyring/`，未设则 `~/.config/...`
  - macOS：无专用分支，回退到同一 XDG 规则（见 `keyring/util/platform_.py`）
  - Windows：`%LOCALAPPDATA%\Python Keyring\`
- entry point 元数据（各发行包的 `.dist-info/entry_points.txt`）与
  `keyring-path` 指向的目录——可写即能新增/替换后端实现。

## 固定到预期后端的最小配置

二选一，配置文件方式对两种启动方式都生效（进程管理器通常拿不到 shell 环境）：

```ini
# ~/.config/python_keyring/keyringrc.cfg
[backend]
default-keyring=keyring.backends.macOS.Keyring
```

或环境变量（写进 service unit 的 `Environment=`，不要写进交互 shell profile）：

```sh
export PYTHON_KEYRING_BACKEND=keyring.backends.macOS.Keyring
```

插件需要属性时，属性只能通过 `KEYRING_PROPERTY_<NAME>` 注入到**实例**，
且在后端构造函数中读取；classproperty（如 `priority`）看不到实例属性。

## 错误配置必须显式失败（已验证）

`verify_pin_and_failures.sh` 实测结论：

- 环境变量/配置指向不存在的类 → `ImportError`/`AttributeError`，进程非零退出，
  **不会**落到自动探测的其它后端。
- 指向不可用后端（如 vault 缺 `KEYRING_PROPERTY_VAULT_PIN`）→ 构造期
  `RuntimeError`，非零退出并指明缺失项。
- 唯一软回退：配置文件缺少 `default-keyring` 选项时，库仅打印
  `Keyring config file contains incorrect values` 警告后继续自动探测。
  因此固定后端必须给出**完整且精确**的类名，不能依赖默认行为。
- 无任何可用后端时自动探测返回 `fail.Keyring`（priority 0），它在首次
  `get_password` 时抛 `NoKeyringError`，而不是静默返回空。
- 附带发现：插件构造函数抛出非 `TypeError` 异常会使整个自动探测崩溃
  （`get_all_keyring` 只抑制 `TypeError`），插件自身必须把不可用表达为
  priority 抛错或 `TypeError`。
