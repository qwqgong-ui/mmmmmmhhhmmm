# 当前运行配置的下行带宽与 perf

`perf-bandwidth.py` 针对正在运行的 mihomo 测试，通过现有透明代理路径发起 HTTP(S) 下载，不修改节点选择、规则、TUN 或服务。默认进程来自 `mihomo.service`，默认物理网卡为 `enp4s0`，可用参数覆盖。依赖 Python 3、PyYAML、curl、perf 和免密 sudo；恢复 Go 符号还需要 Go 和 GNU objcopy。

每轮输出独立目录，保存网卡吞吐、进程 CPU、真实连接路由、curl 有效字节数、perf stat、原始采样和函数报告。脚本通过下载子进程的 `/proc/<pid>/fd` 与 TCP socket 表确定实际源端口，再与 `/connections` 匹配，排除同一端口范围内的其他应用连接。运行中临时把 `kernel.kptr_restrict` 改为 0，退出时恢复原值；因此不要同时启动多个采样脚本。HTTP 403/429 或路由不符合预期时停止测试。Ctrl+C 会结束测试连接并恢复设置。请勿用 SIGKILL 终止脚本。

## 准备离线符号

发行二进制可能移除了 ELF 函数符号。以下操作只修改离线副本，不改变安装文件或正在运行的进程。`perf-go-symbols.go` 从同一个二进制的 `.gopclntab` 恢复函数入口，因此不需要重新构建，也不会把不同构建的地址误配给采样。

在仓库根目录执行：

```bash
bench_dir=$(mktemp -d /tmp/mihomo-bandwidth.XXXXXX)
bench_pid=$(systemctl show mihomo -p MainPID --value)
bench_exe=$(sudo readlink /proc/"$bench_pid"/exe)
mkdir -p "$bench_dir/symbols$(dirname "$bench_exe")"
sudo cat /proc/"$bench_pid"/exe > "$bench_dir/mihomo-running"
go run scripts/perf-go-symbols.go "$bench_dir/mihomo-running" > "$bench_dir/symbols.args"
objcopy @"$bench_dir/symbols.args" "$bench_dir/mihomo-running" "$bench_dir/symbols$bench_exe"
```

## 逐档并发及正式采样

先用 `--no-perf --seconds 12` 做 1、4、8、12/16 并发的递增测试，判断测速源和链路是否出现平台期。不要同时跑 DIRECT 和 HY2。将 `--expect-proxy` 改成当前配置的真实出站名；错误路由会使脚本退出。

本次正式采样命令如下，公网测速源的可用性和限速可能变化：

```bash
python scripts/perf-bandwidth.py --label idle --idle --warmup 0 --seconds 10 \
  --output "$bench_dir" --symfs "$bench_dir/symbols"

python scripts/perf-bandwidth.py --label direct-profile \
  --expect-proxy 本地直连 --connections 12 --warmup 5 --seconds 45 \
  --url https://mirrors.tuna.tsinghua.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso \
  --url https://mirrors.ustc.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso \
  --output "$bench_dir" --symfs "$bench_dir/symbols"

python scripts/perf-bandwidth.py --label hy2-profile \
  --expect-proxy '🇯🇵 h4' --connections 8 --warmup 5 --seconds 45 \
  --url https://speedtest.tokyo2.linode.com/1GB-tokyo2.bin \
  --url https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
  --output "$bench_dir" --symfs "$bench_dir/symbols"
```

curl 的有效字节数包含预热阶段；网卡均值只统计正式阶段且包含协议开销和后台流量。`route_observed_*` 是每秒采样连接计数的下界：请求可能在两次查询之间结束，不能把它当作精确的应用吞吐。`perf stat` 的 `task-clock / 测量秒数` 表示使用了多少个逻辑 CPU；1.0 是占满一个逻辑 CPU。perf 的累计百分比包含子调用，不能相加。

## 独立实例 A/B

可用 `--pid` 和 `--config` 指向已启动的独立实例，并以 `--http-proxy http://127.0.0.1:端口` 显式选择其代理入口。配置中的控制端口和凭据须与该实例一致；脚本仍核验实际连接路由。A/B 两侧应使用相同入口、节点、工具链、PGO 和构建参数。

`--count-io` 将 `syscalls:sys_enter_write` 与 `syscalls:sys_enter_recvmmsg` 加入 `perf stat`。它只统计进程调用次数，不记录每次调用的大小或是否成功，包含 eventfd 等非下载写入。每 MiB 调用数和 CPU 秒/GiB 应使用正式窗口的字节数作分母；不要混用包含预热的应用字节。具体对照结果见 [HY2 批次通知 A/B](../docs/benchmarks/2026-09-22-hy2-stream-read-batching.md)。

## 额外检查小块写回

另起一轮相同流量，预热后可执行短时系统调用追踪。它与常规 CPU 采样分开运行；结果用于调用次数和大小分析，不用来替代常规轮的 CPU 数字。

```bash
sudo perf record -p "$bench_pid" \
  -e syscalls:sys_enter_write,syscalls:sys_exit_write,syscalls:sys_enter_recvmmsg,syscalls:sys_exit_recvmmsg \
  -o "$bench_dir/hy2-syscalls.data" -- sleep 5
sudo perf script -i "$bench_dir/hy2-syscalls.data" > "$bench_dir/hy2-syscalls.txt"
```

原始 perf 和内核符号可能包含其他存量连接的运行信息，输出目录应保留在本机。默认脚本测试的是 TCP 下行；`--upload FILE` 可针对支持 POST 的测试服务发送文件，但本次报告没有上行或 Hybrid QUIC/UDP 的测量结论。
