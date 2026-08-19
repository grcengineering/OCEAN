use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};

use super::{Module, Observer, Tester};

/// Metadata about a registered module, suitable for CLI listings and API responses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    /// "observer" or "tester"
    pub module_type: String,
    pub source_system: String,
    /// Empty for observers.
    pub safety_classification: String,
    /// Empty for observers.
    pub environment_scope: String,
}

/// Thread-safe registry of all registered observers and testers.
#[derive(Default)]
pub struct Registry {
    observers: RwLock<HashMap<String, Arc<dyn Observer>>>,
    testers: RwLock<HashMap<String, Arc<dyn Tester>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_observer(&self, c: Arc<dyn Observer>) {
        self.observers
            .write()
            .unwrap()
            .insert(c.id().to_string(), c);
    }

    pub fn register_tester(&self, t: Arc<dyn Tester>) {
        self.testers.write().unwrap().insert(t.id().to_string(), t);
    }

    pub fn get_observer(&self, id: &str) -> Result<Arc<dyn Observer>> {
        self.observers
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("observer {id:?} not found"))
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
        if let Ok(c) = self.get_observer(id) {
            return Ok(c as Arc<dyn Module>);
        }
        if let Ok(t) = self.get_tester(id) {
            return Ok(t as Arc<dyn Module>);
        }
        Err(anyhow!("module {id:?} not found"))
    }

    pub fn list_observers(&self) -> Vec<Arc<dyn Observer>> {
        self.observers.read().unwrap().values().cloned().collect()
    }

    pub fn list_testers(&self) -> Vec<Arc<dyn Tester>> {
        self.testers.read().unwrap().values().cloned().collect()
    }

    pub fn list_modules(&self) -> Vec<ModuleInfo> {
        let mut infos = Vec::new();

        for c in self.observers.read().unwrap().values() {
            infos.push(ModuleInfo {
                id: c.id().to_string(),
                name: c.name().to_string(),
                version: c.version().to_string(),
                module_type: "observer".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockObserver, MockTester};

    fn make_registry() -> Registry {
        let reg = Registry::new();
        reg.register_observer(Arc::new(MockObserver::new("col.a")));
        reg.register_observer(Arc::new(MockObserver::new("col.b")));
        reg.register_tester(Arc::new(MockTester::safe("test.a")));
        reg
    }

    #[test]
    fn get_observer_found() {
        let reg = make_registry();
        let c = reg.get_observer("col.a").unwrap();
        assert_eq!(c.id(), "col.a");
    }

    #[test]
    fn get_observer_not_found() {
        let reg = make_registry();
        let err = reg.get_observer("nonexistent").err().expect("should fail");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn get_tester_found() {
        let reg = make_registry();
        let t = reg.get_tester("test.a").unwrap();
        assert_eq!(t.id(), "test.a");
    }

    #[test]
    fn get_tester_not_found() {
        let reg = make_registry();
        assert!(reg.get_tester("missing").is_err());
    }

    #[test]
    fn get_module_finds_observer() {
        let reg = make_registry();
        let m = reg.get_module("col.a").unwrap();
        assert_eq!(m.id(), "col.a");
    }

    #[test]
    fn get_module_finds_tester() {
        let reg = make_registry();
        let m = reg.get_module("test.a").unwrap();
        assert_eq!(m.id(), "test.a");
    }

    #[test]
    fn get_module_not_found() {
        let reg = make_registry();
        assert!(reg.get_module("unknown").is_err());
    }

    #[test]
    fn list_observers_returns_all() {
        let reg = make_registry();
        assert_eq!(reg.list_observers().len(), 2);
    }

    #[test]
    fn list_testers_returns_all() {
        let reg = make_registry();
        assert_eq!(reg.list_testers().len(), 1);
    }

    #[test]
    fn list_modules_sorted_by_id() {
        let reg = make_registry();
        let modules = reg.list_modules();
        assert_eq!(modules.len(), 3);
        // Verify sorted
        let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn list_modules_has_correct_types() {
        let reg = make_registry();
        let modules = reg.list_modules();
        let col_count = modules
            .iter()
            .filter(|m| m.module_type == "observer")
            .count();
        let test_count = modules.iter().filter(|m| m.module_type == "tester").count();
        assert_eq!(col_count, 2);
        assert_eq!(test_count, 1);
    }

    #[test]
    fn list_by_type_observer() {
        let reg = make_registry();
        let cols = reg.list_by_type("observer");
        assert_eq!(cols.len(), 2);
        assert!(cols.iter().all(|m| m.module_type == "observer"));
    }

    #[test]
    fn list_by_type_tester() {
        let reg = make_registry();
        let testers = reg.list_by_type("tester");
        assert_eq!(testers.len(), 1);
    }

    #[test]
    fn list_by_source_system() {
        let reg = make_registry();
        // All mocks have source_system = "mock"
        let mock_modules = reg.list_by_source_system("mock");
        assert_eq!(mock_modules.len(), 3);

        let aws_modules = reg.list_by_source_system("aws");
        assert!(aws_modules.is_empty());
    }

    #[test]
    fn tester_info_includes_safety_and_scope() {
        let reg = make_registry();
        let modules = reg.list_modules();
        let tester_info = modules.iter().find(|m| m.module_type == "tester").unwrap();
        assert!(!tester_info.safety_classification.is_empty());
        assert!(!tester_info.environment_scope.is_empty());
    }
}
