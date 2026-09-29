//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use super::{RenewableTokenEntry, RenewableTokenStore};
use crate::token::TokenError;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Key of the flow index: (participant context id, flow id). Flow ids are only unique within a
/// participant context.
type FlowKey = (String, String);

fn flow_key(participant_context_id: &str, flow_id: &str) -> FlowKey {
    (participant_context_id.to_string(), flow_id.to_string())
}

/// Inner storage structure holding all token indices.
struct InnerStore {
    /// Primary storage indexed by hashed_refresh_token
    entries_by_hash: HashMap<String, RenewableTokenEntry>,
    /// Secondary index by id for id-based lookups
    entries_by_id: HashMap<String, RenewableTokenEntry>,
    /// Secondary index from (participant context, flow) to the ids of every entry issued for it,
    /// oldest first. A flow may be issued more than one token (e.g. a repeated start), and all of
    /// them must stay revocable.
    ids_by_flow: HashMap<FlowKey, Vec<String>>,
}

impl InnerStore {
    fn insert(&mut self, entry: RenewableTokenEntry) {
        self.entries_by_hash
            .insert(entry.hashed_refresh_token.clone(), entry.clone());
        self.ids_by_flow
            .entry(flow_key(&entry.participant_context_id, &entry.flow_id))
            .or_default()
            .push(entry.id.clone());
        self.entries_by_id.insert(entry.id.clone(), entry);
    }
}

/// In-memory renewable token store for testing and development.
///
/// Uses a single lock to protect all indices, ensuring atomic updates and simplicity.
pub struct MemoryRenewableTokenStore {
    store: RwLock<InnerStore>,
}

impl MemoryRenewableTokenStore {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(InnerStore {
                entries_by_hash: HashMap::new(),
                entries_by_id: HashMap::new(),
                ids_by_flow: HashMap::new(),
            }),
        }
    }
}

impl Default for MemoryRenewableTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RenewableTokenStore for MemoryRenewableTokenStore {
    async fn save(&self, entry: RenewableTokenEntry) -> Result<(), TokenError> {
        self.store.write().await.insert(entry);
        Ok(())
    }

    async fn find_by_renewal(&self, hash: &str) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .entries_by_hash
            .get(hash)
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(hash))
    }

    async fn find_by_id(&self, id: &str) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .entries_by_id
            .get(id)
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(id))
    }

    async fn find_by_flow_id(
        &self,
        participant_context_id: &str,
        flow_id: &str,
    ) -> Result<RenewableTokenEntry, TokenError> {
        let store = self.store.read().await;
        store
            .ids_by_flow
            .get(&flow_key(participant_context_id, flow_id))
            .and_then(|ids| ids.last())
            .and_then(|id| store.entries_by_id.get(id))
            .cloned()
            .ok_or_else(|| TokenError::token_not_found(flow_id))
    }

    async fn remove_by_flow_id(&self, participant_context_id: &str, flow_id: &str) -> Result<(), TokenError> {
        let mut store = self.store.write().await;
        let ids = store
            .ids_by_flow
            .remove(&flow_key(participant_context_id, flow_id))
            .ok_or_else(|| TokenError::token_not_found(flow_id))?;

        for id in ids {
            if let Some(entry) = store.entries_by_id.remove(&id) {
                store.entries_by_hash.remove(&entry.hashed_refresh_token);
            }
        }
        Ok(())
    }

    async fn update(&self, old_hash: &str, new_entry: RenewableTokenEntry) -> Result<(), TokenError> {
        let mut store = self.store.write().await;

        let old_entry = store
            .entries_by_hash
            .remove(old_hash)
            .ok_or_else(|| TokenError::token_not_found(old_hash))?;

        store.entries_by_id.remove(&old_entry.id);
        let old_key = flow_key(&old_entry.participant_context_id, &old_entry.flow_id);
        if let Some(ids) = store.ids_by_flow.get_mut(&old_key) {
            ids.retain(|id| id != &old_entry.id);
            if ids.is_empty() {
                store.ids_by_flow.remove(&old_key);
            }
        }

        store.insert(new_entry);
        Ok(())
    }
}
