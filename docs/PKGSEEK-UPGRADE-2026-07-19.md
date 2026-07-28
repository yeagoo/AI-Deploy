# PkgSeek 生产升级与 opsctl 安全复盘（2026-07-19）

## 结论

PkgSeek 已部署到 `v0.1.13` / `3871c27c3c2bbb671edf30a9bfdcb92e5b607c82`。
本次修复了 SSR 内部读取共享公共匿名限流桶的问题，并把严格 SEO 审计从最初的
79 条告警收敛到生产 120 个目标 0 error、0 warning。生产只替换 API/Web；
PostgreSQL、Valkey、Meilisearch 和 CNNVD 数据均未重建。

opsctl 只读检查最终报告 PkgSeek 备份就绪为 `ready`。同时保留并报告了恢复演练
磁盘满和周更任务退出 137 的失败证据，没有 reset failure 或删除证据来制造绿色
状态。

## 安全边界与变更范围

- Web SSR 使用 Compose 网络内、认证、GET/HEAD-only 的 API 监听器 8788。
- 8788 不发布到主机；公共 API 仍只映射 `127.0.0.1:8787`。
- 内部认证标记不可由公共请求头直接伪造，公共端口继续执行 Governor 和路由限流。
- 内部 POST 返回 405；Web BFF 写路径仍走公共 API。
- 严格预检验证精确监听地址/URL、内部密钥长度与不复用，并拒绝 Compose 发布
  target 8788。
- 每次切换都持有 `/run/lock/pkgseek-maintenance.lock`，使用 `--no-build --no-deps
  api web`；有状态容器 ID 在整个升级中保持不变。
- 运行配置先创建 0600/root 的版本化备份，只更新不可变镜像引用与 manifest
  绑定；没有输出密钥值。

生产边界测试：内部无密钥 401、有效 GET 200、POST 405；真实内部头发到公共端口
仍是 30 次 200、10 次 429；80 次内部直读及分 8 批的 80 个 SSR 页面全部 200，
检查窗口没有 API 不可达、未捕获异常或内部服务器错误。

## 发布证据

发布依次形成三个不可变版本：

- `v0.1.11` / `b1838a7`：内部只读边界及主要 SEO 修复。
- `v0.1.12` / `1a40c4c`：从实时索引发现可验证 CVE 审计样本。
- `v0.1.13` / `3871c27`：将最后两段中文描述限制在 90 字符内并增加回归测试。

每个版本通过校验过的增量 Git bundle 传输并签出精确提交；生产原生 arm64 发布
生成五个镜像归档、镜像元数据、Trivy 报告、CycloneDX SBOM、隔离非 root 功能
测试、回滚归档、manifest 和 SHA-256。最终 API/Web 镜像标签与 OCI revision 都
指向 `3871c27c3c2bbb671edf30a9bfdcb92e5b607c82`。

本地和生产门禁包括 Rust 186 项测试、Web 119 项测试、fmt、Clippy、ESLint、
Next.js 生产构建、部署预检契约、发布契约、版本一致性、diff check、staged
gitleaks、严格 preflight/smoke 和严格生产 SEO。最终 SEO 为 120 checked、117
HTML、0 error、0 warning、0 slow page。

## 数据与运行状态

- CNNVD：`healthy`，347,659 条；没有重复 import 或 dump。
- CVE：`healthy`，13,686,248 条。
- PostgreSQL 容器：`0922f51bc8e0`。
- Valkey 容器：`385b18773baf`。
- Meilisearch 容器：`6fc51b72139f`。
- 最终 API：`70133f101b5b`；最终 Web：`9d2fcea778fe`。
- 根分区最终 83%，约 42 GB 可用。
- PkgSeek daily/weekly timer 与 opsctl restore-drill timer 均已恢复为 active。

## 恢复演练事故

升级期间 `opsctl-restore-drill@pkgseek.service` 同时运行独立 `--rm` 恢复容器，
在约 33 分钟内把根分区写满，导致 PkgSeek `/ready` 暂时返回 503。处置严格限定为
停止该 service 和它对应的一次性容器；没有清理备份仓库、生产卷、发布目录或
CNNVD 数据。释放一次性容器占用后恢复约 45 GB 空间，生产健康返回 200。

service 因主动停止保留 `failed`、SIGTERM 15 结果，timer 仍 active。只读
`opsctl backup readiness` 仍显示 PkgSeek 为 ready，但这不能抹掉调度 unit 的失败
事实。恢复演练下次运行前应增加：

1. 运行前磁盘余量和预计恢复大小门禁。
2. 独立临时目录/文件系统配额，以及明确的空间上限。
3. 达到低水位时先停止隔离演练并保存证据，不影响生产 readiness。
4. 发布制品、恢复暂存和生产数据的并发空间预算。
5. 演练结束时对一次性容器和暂存目录做精确、可审计的回收，禁止广泛 prune。

另有既存的 `pkgseek-refresh@weekly.service` 在 1 小时 49 分后退出 137；内核日志
确认 `indexer` 在 Docker memory cgroup 内约 4.0 GiB anonymous RSS 时被 OOM kill，
不是 systemd 的 24 小时启动超时。其 timer 仍 active。应独立检查索引阶段的
有界集合、分批策略、并发度、容器内存预算与阶段可恢复性，不能通过提高全局权限
或取消失败门禁解决。

## 快慢路径建议

日常 CVE 更新不需要复制这次完整流程：

- 数据日更：只做 CVE 增量索引和搜索增量同步。
- 周更完整性：运行重型全量任务，但先验证超时、磁盘和资源预算。
- 应用发布：仅代码、迁移、基础镜像或部署契约变化时构建/扫描镜像。
- 全量 dump：与 CVE 日更解耦并降低频率；不能把部分结果标记为完整 dump。

本次慢的主要原因是安全功能开发、三次不可变补丁、两轮完整生产 SEO 审计，以及
同时发生的恢复演练磁盘事故，不是每次 CVE 数据增量不可避免的固定成本。

## 回滚约束

保留 v0.1.11、v0.1.12、v0.1.13 的发布目录、镜像和运行配置备份。回滚只在维护
锁下恢复精确配置并替换 API/Web；不删除 CNNVD、不重建有状态容器、不随意降级
数据库。任何数据库兼容变更都必须重新满足备份、恢复、审批、路径和证据门禁。

## 发行版本展示规范

PkgSeek 的公开版本族与精确索引快照必须分开维护，不能因为数据源更新到新的点版本，
就把主导航、页面标题、选择器和 canonical URL 一起改成点版本：

- `slug`/`label` 表示稳定的公开版本族；`release` 表示数据库和 API 查询使用的精确
  仓库、安装介质或 feed 快照。
- RHEL 公开为 `10`、`9`，当前精确快照分别为 `10.2`、`9.8`；OpenWrt 公开为
  `25.12`，当前精确快照为 `25.12.5`。
- 旧的精确版本 URL 必须继续可解析，并 canonicalize 到版本族 URL；后端查询仍必须
  使用精确 `release`，快照号作为次级来源证据展示。
- 禁止机械删除最后一段数字。Ubuntu `24.04`、openSUSE Leap `15.6`、EUS、服务包、
  ABI 或仓库套件等真实兼容边界必须按上游语义单独判断。
- 每次调整版本映射，都必须测试版本族输入和旧精确输入、检查 canonical、确认 API
  仍查询精确快照，并通过 Web 测试、lint、TypeScript/生产构建后再部署。

项目级强制规则位于 `~/pkgseek/AGENTS.md`，完整说明位于
`~/pkgseek/docs/VERSION-PRESENTATION.md`。

## v0.1.14 快速迭代实测

2026-07-19 后续以提交 `8df98919406ab8225de4b5fbe7eda8f7e5b410a3` 发布
v0.1.14，将 RHEL 的公开版本收敛为 10/9、OpenWrt 收敛为 25.12，同时保留
10.2/9.8/25.12.5 作为精确索引坐标。旧 RHEL 点版本 URL 继续返回 200，并
canonicalize 到版本族 URL。

生产原生 arm64 完整资格审查实测 375 秒（6 分 15 秒）：Rust 自身重编译约
141 秒、Web 生产构建约 83 秒，其余约 151 秒用于五镜像扫描/SBOM、隔离功能
检查、归档与 manifest。维护锁内运行配置切换和健康收敛少于两分钟；加上严格
预检及外部验证，从已确认提交到完成生产验证约为十分钟级，而不是固定一小时。

本次仍遵循现有五镜像绑定 manifest，匹配替换 API/Web；PostgreSQL、Valkey、
Meilisearch 容器和卷均未重建，CNNVD 保持 healthy、347,659 条。运行配置在切换
前创建 0600 版本化备份，旧 API/Web 镜像与 v0.1.13 证据保留，可做精确回滚。

真正的 Web-only 分钟级发布尚未实现。后续应增加 fail-closed 差异分类器、单 Web
镜像扫描/SBOM/归档、与上一版已审查 API/有状态镜像的组合 provenance、严格预检
契约测试，以及只替换 Web 的锁内自动回滚。任何 Rust、迁移、Compose、基础镜像、
API 或数据模式变化必须自动回到完整发布路径；禁止通过跳过扫描、证据或健康门禁
换取速度。

完整部署记录位于 `~/pkgseek/docs/DEPLOYMENT-v0.1.14-2026-07-19.md`。

## v0.1.15 生产部署与契约纠错

2026-07-19 将 `release/v0.1.15` 推送至远端，精确提交为
`771d2edaebc9a96387e96f4499c1260f7b4b7c9c`；未创建未经授权的 tag。生产只重建
API/Web，PostgreSQL、Valkey、Meilisearch 容器 ID 和数据卷未变化。原生 arm64
五镜像资格审查耗时 372 秒，严格预检和上线后完整 smoke 均为 0 warning。

线上验证确认 RHEL `/10` 为 canonical，旧 `/10.2` 保持 200 并 canonicalize 到
`/10`；主标签使用 10，精确 10.2 仅作为次级索引坐标。OpenWrt 主标签和输入使用
25.12，精确快照仍为 25.12.5。CNNVD dataset healthy 347,659 条，符合详情 sitemap
质量的 CVE 别名 339,001 条，超过 300,000 门禁。

本次还实际验证了 fail-closed 回滚：旧脚本约定中的 `compose.yaml` 文件名、首次草稿
中的 manifest 键，以及猜测的 `PKGSEEK_RELEASE_MANIFEST*` 均被真实文件/严格预检
拒绝；第三次在候选环境文件已替换后触发自动回滚，v0.1.14 API/Web 健康恢复。最终
按仓库实际的 `docker-compose*.yml` 和
`PKGSEEK_LOCAL_RELEASE_MANIFEST{,_SHA256}` 契约完成切换。

以后发布脚本必须先只读枚举精确提交中的 Compose 文件名、读取
`scripts/deploy-preflight.sh` 及其契约测试、只列出生产 env 键名而不读取值，并先对
候选环境执行 Compose render 和 strict preflight。禁止从上次脚本推断文件名或环境
键；维护锁、manifest SHA、状态容器 ID 断言、有限健康等待和自动回滚仍是强制门禁。

完整记录位于 `~/pkgseek/docs/DEPLOYMENT-v0.1.15-2026-07-19.md`。
