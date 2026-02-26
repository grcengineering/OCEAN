use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};

use super::{Collector, Tester, Module};

/// Metadata about a registered module, suitable for CLI listings and API responses.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    /// "collector" or "tester"
    pub module_type: String,
    pub source_system: String,
    /// Empty for collectors.
    pub safety_classification: String,
    /// Empty for collectors.
    pub environment_scope: String,
}

/// Thread-safe registry of all registered collectors and testers.
#[derive(Default)]
pub struct Registry {
    collectors: RwLock<HashMap<String, Arc<dyn Collector>>>,
    testers: RwLock<HashMap<String, Arc<dyn Tester>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_collector(&self, c: Arc<dyn Collector>) {
        self.collectors.write().unwrap().insert(c.id().to_string(), c);
    }

    pub fn register_tester(&self, t: Arc<dyn Tester>) {
        self.testers.write().unwrap().insert(t.id().to_string(), t);
    }

    pub fn get_collector(&self, id: &str) -> Result<Arc<dyn Collector>> {
        self.collectors
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("collector {id:?} not found"))
    }

    pub fn get_tester(&self, id: &str) -> Result<Arc<dyn Tester>> {
        self.testers
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("tester {id:?} not found"))
    }

    pub fn get_module(&self, id: &str) -> Result<Arc<dyn Module>> {
        if let Ok(c) = self.get_collector(id) {
            return Ok(c as Arc<dyn Module>);
        }
        if let Ok(t) = self.get_tester(id) {
            return Ok(t as Arc<dyn Module>);
        }
        Err(anyhow!("module {id:?} not found"))
    }

    pub fn list_collectors(&self) -> Vec<Arc<dyn Collector>> {
        self.collectors.read().unwrap().values().cloned().collect()
    }

    pub fn list_testers(&self) -> Vec<Arc<dyn Tester>> {
        self.testers.read().unwrap().values().cloned().collect()
    }

    pub fn list_modules(&self) -> Vec<ModuleInfo> {
        let mut infos = Vec::new();

        for c in self.collectors.read().unwrap().values() {
            infos.push(ModuleInfo {
                id: c.id().to_string(),
                name: c.name().to_string(),
                version: c.version().to_string(),
                module_type: "collector".to_string(),
                source_system: c.source_system().to_string(),
                safety_classification: String::new(),
                environment_scope: String::new(),
            });
        }

        for t in self.testers.read().unwrap().values() {
            infos.push(ModuleInfo {
                id: t.id().to_string(),
                name: t.name().to_string(),
                version: t.version().to_string(),
                module_type: "tester".to_string(),
                source_system: t.source_system().to_string(),
                safety_classification: t.safety_class().to_string(),
                environment_scope: t.environment_scope().to_string(),
            });
        }

        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    pub fn list_by_type(&self, module_type: &str) -> Vec<ModuleInfo> {
        self.list_modules()
            .into_iter()
            .filter(|m| m.module_type == module_type)
            .collect()
    }

    pub fn list_by_source_system(&self, system: &str) -> Vec<ModuleInfo> {
        self.list_modules()
            .into_iter()
            .filter(|m| m.source_system == system)
            .collect()
    }
}
