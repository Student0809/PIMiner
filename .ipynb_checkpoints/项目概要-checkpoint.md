这个项目的“训练”并不是微调模型参数，而是让一个攻击 Agent 在多个数据集、多个目标模型上反复试错，然后把成功经验整理成 Markdown 攻击策略库。它本质上是“迭代攻击 + 外部记忆/策略蒸
  馏”，而不是 SGD、RLHF 或 LoRA 训练。

  ## 一、整体训练思路

  核心循环是：

  Benchmark 样本
     ↓
  Router 为样本挑选 Top-3 攻击策略
     ↓
  Attacker 生成注入文本
     ↓
  把注入插入工具返回内容，调用目标模型
     ↓
  Benchmark 判断恶意目标是否成功
     ↓
  失败：根据目标模型反馈继续改写，最多 10 次
  成功/耗尽
     ↓
  Digestor 汇总成功和失败模式，更新策略库
     ↓
  下一个数据集/目标模型复用更新后的策略库

  项目自己的概括是 Init → Route → Attack → Digest，见 README.md:159。

  ### 1. 冷启动

  如果把现有策略清空，只留下 _TEMPLATE.md，第一个训练数据集没有具体攻击经验，就使用结构模板从零探索。

  找到成功攻击后，Digestor 会创建第一个真正的策略文件。仓库同时提供了一个已经训练好的 strategy_library，所以默认情况下可以不训练直接测试；从头复现实验则需要先备份并清空已有策
  略，见 README.md:93。

  ### 2. Router 选择候选策略

  当策略库已有内容时，每个样本先交给 Router。Router 根据以下信息选 Top-3：

  - 目标模型，例如 GPT-5、GPT-5-nano、Claude Haiku。
  - 用户原始任务。
  - 恶意注入目标。
  - 注入出现在哪种工具输出或页面结构里。
  - 现有策略的适用模型、成功案例和失败条件。

  Attacker 会看到这三个完整策略文件，可以：

  - 直接套用某一个；
  - 组合多个策略；
  - 如果都不适用，走 _template_cold_start 从头设计。

  这也是为什么策略文件里不仅有一个 prompt，还保存了适用范围、失败条件、目标模型和完整成功案例。

  ### 3. 对单个样本进行多轮迭代攻击

  Attacker 生成两个区块：

  <analysis>
  分析上一次为什么失败，本轮准备改变什么
  </analysis>

  <injection>
  真正注入到工具返回内容里的攻击文本
  </injection>

  系统把 <injection> 替换进样本的占位符，然后实际调用被攻击的目标模型。

  如果目标模型没有完成恶意目标，Attacker 会读取反馈并修改攻击方法；不是简单同义改写，而是要求根据失败轨迹改变攻击结构，例如：

  - 模型把注入当成普通数据而忽略；
  - 模型要求用户确认；
  - 模型调用了相邻工具，但没调用目标工具；
  - 工具参数不符合 judge 的精确要求；
  - 注入所声称的身份或权限不可信。

  达到恶意目标就是 hit；用完迭代次数仍未成功就是 miss。状态判断代码在 iterative_attack_orchestrator/iterative_attack_claude_code.py:1377。

  主实验每个样本最多尝试 10 次，见 experiments/main_exp.yaml:10。

  ### 4. Digest：真正被“训练”的东西

  一个 (benchmark, target model) 数据集跑完后，Digestor 分析：

  - 所有成功攻击；
  - 显著的失败聚类；
  - Router 原来选择了什么策略；
  - 最终起作用的核心机制是什么。

  然后按三种情况更新策略库：

  1. 成功案例符合已有策略：追加为新的 in-context example。
  2. 机制相同但适用面更广：追加案例，并扩大策略的适用范围说明。
  3. 是全新的机制：创建新的策略 Markdown 文件。

  失败也会用于修正某个策略的“推荐模型范围”和“预期失败条件”。具体规则见 .claude/commands/digest.md:22。

  所以它学到的是：

  - 可复用的攻击机制；
  - 哪类模型容易被哪类策略攻破；
  - 哪种工具输出表面适合哪种注入结构；
  - 完整的成功注入示例；
  - 已观察到的失败边界。

  训练完成后会把策略库快照保存到每个运行目录的 strategy_library_post/，见 piminer_train_parallel.sh:321。

  ### 5. 跨模型顺序训练

  训练数据集按顺序执行，原因是后面的 Router 必须使用前面 Digestor 刚总结出的策略。

  当前主实验顺序是：

  - AgentDojo × GPT-5-nano
  - AgentDojo × GPT-5
  - AgentDojo × Claude Haiku
  - IPI-Arena × GPT-5-nano
  - IPI-Arena × GPT-5
  - IPI-Arena × Claude Haiku
  - AgentDojo × Claude Sonnet
  - IPI-Arena × Claude Sonnet

  具体见 experiments/main_exp.yaml:18。

  同一个 benchmark 在不同目标模型上使用相同训练样本。也就是说它想学习的是：

  > 同一个攻击场景在不同能力、不同安全特性的模型上需要怎样调整策略。

  注意配置文件第 17 行注释还写着 IPI-Arena 0..14，但实际配置已经全部是 n: 20；执行时以 YAML 条目的 n: 20 为准，这是一个没有同步更新的旧注释。

  ## 二、训练和测试的区别

  训练阶段：

  - 策略库会被修改；
  - 每个数据集结束后运行 Digest；
  - 默认是白盒反馈，可以看到完整目标轨迹；
  - 数据集之间串行，样本内部可以并行。

  测试阶段：

  - 策略库完全冻结；
  - 不运行 Digest；
  - 使用黑盒模式；
  - Attacker 只能看到目标最终输出和二元成功/失败结果；
  - 不保存完整内部轨迹；
  - 不同目标模型可以并行测试。

  黑盒和冻结要求见 ORCHESTRATION.md:57。

  最终指标主要是 ASR：

  ASR = hit 样本数 / 总测试样本数

  ## 三、数据集从哪里来

  README 明确说项目建立在三个外部 benchmark 上：AgentDojo、InjecAgent 和 IPI-Arena，另外迭代攻击思路受到 PAIR 启发，见 README.md:213。

  ### 1. AgentDojo

  上游来源：

  - ETH Zurich SPY Lab 的 AgentDojo
  - 上游仓库：ethz-spylab/agentdojo

  本项目实际使用已经预处理好的：

  data/agentdojo/agentdojo_injection_steps.jsonl

  本地共有 1,234 个 injection-step 样本：

   Suite        数量
  ━━━━━━━━━━━  ━━━━━━
   workspace     742
  ───────────  ──────
   travel        203
  ───────────  ──────
   slack         145
  ───────────  ──────
   banking       144

  每一行大致包含：

  - 用户原始任务；
  - 恶意注入任务；
  - AgentDojo 的用户任务/攻击任务 ID；
  - 工具执行到哪个 step；
  - 哪些注入向量在该 step 对模型可见；
  - 带 {INJECTION:...} 占位符的真实工具输出上下文。

  运行时使用 AgentDojo benchmark v1.2.2，对应加载逻辑见 benchmarks/agentdojo/dataset.py:126，安装的 Python 包固定为 agentdojo==0.1.35。

  需要注意：仓库没有保留生成这个 AgentDojo JSONL 的独立构建脚本。因此能确定它来自 AgentDojo 的任务、注入任务和执行轨迹，但仅靠当前仓库不能一键重新生成完全相同的 1,234 行文件。
  这一点的可复现性说明弱于另外两个数据集。

  ### 2. IPI-Arena

  上游来源：

  - GraySwanAI 的 ipi_arena_os
  - 上游项目已经完整 vendored 到：
    data/ipi_arena/repo

  - 获取地址直接写在 data/ipi_arena/fetch.sh:1。

  共有 41 个 behavior：

   类型       数量
  ━━━━━━━━━  ━━━━━━
   tool         18
  ─────────  ──────
   coding       15
  ─────────  ──────
   browser       8

  上游说明见 IPI-Arena README (data/ipi_arena/repo/README.md:1)。

  PIMiner 用 data/ipi_arena/build_rows.py:1 把上游每个 behavior JSON 转换为统一的 ipi_arena_rows.jsonl：

  - {fill} 变成注入位置；
  - system prompt、历史消息和工具定义被保留；
  - tool/coding 样本通常直接用工具调用 judge；
  - browser 样本会渲染 HTML/截图，并走上游多步 harness、WorldSim 和 tool/LLM judges。

  这里训练的不是 IPI-Arena 官方公布的 95 条攻击字符串，而是使用它的 41 个行为场景，让 PIMiner 自己生成攻击字符串。

  ### 3. InjecAgent

  项目代码说明它使用的是：

  > PISmith 所使用的 InjecAgent 数据版本。

  构建过程见 data/injecagent/build_rows.py:1。

  原始文件是：

  - train.json：310 条；
  - test.json：100 条；
  - eval.json：100 条。

  但构建 PIMiner 数据池时只合并 train.json + test.json，不使用 eval.json，因此最终：

  data/injecagent/injecagent_rows.jsonl

  共有 410 条：

   类型                               数量
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━
   Direct Harm，直接/物理/金融伤害     268
  ─────────────────────────────────  ──────
   Data Stealing，数据窃取             142

  其场景已经假设“用户工具被调用过”，攻击文本被填进工具返回值里的 <Attacker Instruction>。如果目标模型下一步调用指定的 attacker tool，就算攻击成功，见 data/injecagent/
  build_rows.py:9。

  当前 main_exp.yaml 并没有使用 InjecAgent；它有独立的 experiments/injecagent.yaml，而且目前只配置了 GPT/OpenAI 模型的测试，没有配置训练段。

  ## 四、训练集和测试集如何隔离

  数据池会先按固定随机种子 42 洗牌，然后抽样。

  在同一个 benchmark 上：

  - 不同目标模型共享同一批训练样本；
  - 测试初始化时读取训练运行目录；
  - 按 (suite, user_task, injection_task, step) 精确排除所有训练过的行；
  - 再从剩余样本中选测试样本。

  所以真正的隔离不是单纯依赖 offset，而是按样本身份做集合差。相关说明见 ORCHESTRATION.md:63。

  ## 一句话总结

  PIMiner 是在训练一个“会积累经验的提示注入攻击 Agent”：它用 AgentDojo、IPI-Arena 和 InjecAgent 的任务场景反复攻击不同目标模型，把成功和失败经验蒸馏为可路由、可迁移的 Markdown
  策略库，最后在未见过的模型和 held-out 样本上冻结策略库评估 ASR；它并没有更新任何底层 LLM 的权重。