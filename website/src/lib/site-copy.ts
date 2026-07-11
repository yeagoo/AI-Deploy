import type { Locale } from './i18n';

type LandingCopy = {
  eyebrow: string;
  title: string;
  description: string;
  primaryCta: string;
  secondaryCta: string;
  languageLabel: string;
  languageName: string;
  signalTitle: string;
  signals: readonly (readonly [string, string])[];
  proofTitle: string;
  proofBody: string;
  workflowTitle: string;
  workflow: readonly (readonly [string, string, string])[];
  capabilitiesTitle: string;
  capabilities: readonly (readonly [string, string])[];
  calloutTitle: string;
  calloutBody: string;
  finalTitle: string;
  finalBody: string;
  footer: string;
};

export const siteCopy = {
  zh: {
    eyebrow: '单机部署安全控制器 / v0.6 系列',
    title: '让每一次服务器变更，先有证据，再有动作。',
    description:
      'opsctl 把注册表、备份、恢复、审批与审计放进同一条可验证工作流。它默认只读，拒绝模糊授权，并把高风险操作留给明确的人类决策。',
    primaryCta: '开始使用',
    secondaryCta: '理解安全模型',
    languageLabel: 'English',
    languageName: '中文',
    signalTitle: '当前控制面',
    signals: [
      ['READ', '默认只读'],
      ['PLAN', '计划先行'],
      ['PROVE', '证据闭环'],
      ['HUMAN', '人工批准'],
    ],
    proofTitle: '不是脚本集合，是操作契约。',
    proofBody:
      '每条命令都围绕同一个问题设计：在改变生产环境之前，我们能否证明目标、影响范围、恢复路径和授权边界？',
    workflowTitle: '四段式安全工作流',
    workflow: [
      ['01', '登记', '用 YAML registry 声明服务、端口、域名、卷与备份策略。'],
      ['02', '检查', '扫描真实状态，解释漂移，生成不执行的计划与风险结论。'],
      ['03', '举证', '创建快照、验证备份、执行隔离恢复，并签署证据链。'],
      ['04', '交接', '只有具体、未过期的人工批准才能推进受控执行。'],
    ],
    capabilitiesTitle: '一个 CLI，覆盖生产变更的关键断点',
    capabilities: [
      ['Registry', '把服务器意图变成可审查、可验证的事实源。'],
      ['Preflight', '在执行前拦截端口冲突、卷风险和缺失备份。'],
      ['Recovery', '恢复到隔离目录，校验文件、哈希和数据库特征。'],
      ['Evidence', 'Ed25519 签名、审计 checkpoint 与可恢复归档。'],
      ['Scheduler', '全局串行锁、有限等待和确定性时间分散。'],
      ['MCP / TUI', '面向 AI 的只读工具与面向运维的终端视图。'],
    ],
    calloutTitle: '危险操作不会被“自动化”包装成安全。',
    calloutBody:
      'opsctl 不会自动批准，也不会删除 Docker 卷。计划、证据和人工执行是刻意分开的边界。',
    finalTitle: '从一次只读检查开始。',
    finalBody: '安装后先验证 registry 与运行环境，再进入备份和恢复流程。',
    footer: '为可恢复、可审计的单机生产环境而设计。',
  },
  en: {
    eyebrow: 'Single-server deployment safety controller / v0.6 series',
    title: 'Every server change starts with evidence—not execution.',
    description:
      'opsctl brings registry, backup, recovery, approval, and audit into one verifiable workflow. It is read-only by default, rejects vague authority, and leaves high-risk actions to explicit human decisions.',
    primaryCta: 'Get started',
    secondaryCta: 'Read the safety model',
    languageLabel: '中文',
    languageName: 'English',
    signalTitle: 'Control plane status',
    signals: [
      ['READ', 'Read-only first'],
      ['PLAN', 'Plan before change'],
      ['PROVE', 'Close the evidence loop'],
      ['HUMAN', 'Human approval'],
    ],
    proofTitle: 'Not a bag of scripts. An operations contract.',
    proofBody:
      'Every command is designed around one question: before production changes, can we prove the target, blast radius, recovery path, and authority boundary?',
    workflowTitle: 'A four-stage safety workflow',
    workflow: [
      ['01', 'Declare', 'Describe services, ports, domains, volumes, and backup policy in YAML.'],
      ['02', 'Inspect', 'Observe reality, explain drift, and produce non-executing plans and risk decisions.'],
      ['03', 'Prove', 'Create snapshots, verify backups, restore in isolation, and sign the evidence chain.'],
      ['04', 'Handoff', 'Only specific, unexpired human approval can advance controlled execution.'],
    ],
    capabilitiesTitle: 'One CLI for the critical breakpoints in production change',
    capabilities: [
      ['Registry', 'Turn server intent into a reviewable, validated source of truth.'],
      ['Preflight', 'Block port conflicts, volume risk, and missing backup evidence.'],
      ['Recovery', 'Restore in isolation and verify files, hashes, and database signatures.'],
      ['Evidence', 'Ed25519 signatures, audit checkpoints, and restorable archives.'],
      ['Scheduler', 'Global serialization, bounded waiting, and deterministic spreading.'],
      ['MCP / TUI', 'Read-only tools for AI and an operator-focused terminal view.'],
    ],
    calloutTitle: 'Dangerous operations do not become safe by calling them automation.',
    calloutBody:
      'opsctl does not auto-approve and does not delete Docker volumes. Planning, evidence, and human execution are deliberately separate boundaries.',
    finalTitle: 'Start with a read-only check.',
    finalBody: 'Validate the registry and runtime before entering backup and recovery workflows.',
    footer: 'Designed for recoverable, auditable single-server production.',
  },
} as const satisfies Record<Locale, LandingCopy>;
