/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! 锁毒化恢复助手（生产代码锁获取的统一出口，2026-09-01 决策：
//! 不使用 expect——毒化时告警并恢复，不 panic）。
//!
//! 机制：`std::sync` 锁在持锁线程 panic 时经栈展开**正常释放**并打上
//! poisoned 标记——后续 [`lock`] 立即返回（非阻塞），仅以
//! `Err(PoisonError(guard))` 包装。本助手取回 guard 继续执行并告警一次；
//! guard 正常释放后毒化标记自愈（锁恢复健康）。
//!
//! 状态一致性依据：本 crate 全部临界区内无 panic 源（validator 回调均在
//! 锁外执行），毒化前提是锁外/未来的程序 bug——恢复拿到的是变更前的
//! 完整旧状态，fail-closed 方向不受影响。
//!
//! 告警经**外部 `log` 门面**直通全局 logger，不经 [`crate::logging::emit`]
//! ——后者会触达 CALLBACK 锁，在 logging 模块自身锁恢复时构成重入死锁。

/// 锁获取结果（`Mutex/RwLock` 的 `lock/read/write`）→ 值/守卫。
///
/// 毒化：告警一次（含语义名，不含敏感信息）+ `into_inner()` 恢复。
pub(crate) fn recovered<T>(result: std::sync::LockResult<T>, what: &'static str) -> T {
    result.unwrap_or_else(|poisoned| {
        log::error!(target: "proxy", "[{what}] lock poisoned; recovered");
        poisoned.into_inner()
    })
}
