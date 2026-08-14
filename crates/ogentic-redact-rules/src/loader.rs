//! Rule-pack loader implementation.
//!
//! Loads built-in rule packs (privilege, PHI, MNPI) from embedded JSON data
//! and validates them before returning.

use crate::{RulePack, RulePackCategory, RulePackError};

/// Loader for rule packs.
///
/// The loader provides access to the three built-in rule packs: privilege,
/// PHI, and MNPI. Each pack is validated on load to ensure all regex patterns
/// compile and the structure is well-formed.
pub struct Loader;

impl Loader {
    /// Creates a new rule-pack loader.
    pub fn new() -> Self {
        Loader
    }

    /// Loads a rule pack by category.
    ///
    /// # Arguments
    /// * `category` - The category of rule pack to load.
    ///
    /// # Returns
    /// * `Ok(RulePack)` - The validated rule pack.
    /// * `Err(RulePackError)` - If the pack fails to load or validate.
    pub fn load_pack(&self, category: RulePackCategory) -> Result<RulePack, RulePackError> {
        let json_data = match category {
            RulePackCategory::Privilege => include_str!("../packs/privilege.json"),
            RulePackCategory::PHI => include_str!("../packs/phi.json"),
            RulePackCategory::MNPI => include_str!("../packs/mnpi.json"),
        };

        let pack: RulePack = serde_json::from_str(json_data).map_err(|e| {
            RulePackError::SerdeError(format!("failed to parse {} rule pack: {}", category, e))
        })?;

        pack.validate()?;

        Ok(pack)
    }

    /// Loads all three rule packs.
    ///
    /// # Returns
    /// A vector of all three rule packs (privilege, PHI, MNPI) if all load
    /// and validate successfully. Returns an error on the first failure.
    pub fn load_all(&self) -> Result<Vec<RulePack>, RulePackError> {
        let packs = vec![
            self.load_pack(RulePackCategory::Privilege)?,
            self.load_pack(RulePackCategory::PHI)?,
            self.load_pack(RulePackCategory::MNPI)?,
        ];

        Ok(packs)
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_creates_successfully() {
        let _loader = Loader::new();
    }

    #[test]
    fn test_load_privilege_pack() {
        let loader = Loader::new();
        let pack = loader.load_pack(RulePackCategory::Privilege);
        assert!(pack.is_ok(), "privilege pack should load");
        let pack = pack.unwrap();
        assert_eq!(pack.category, RulePackCategory::Privilege);
    }

    #[test]
    fn test_load_phi_pack() {
        let loader = Loader::new();
        let pack = loader.load_pack(RulePackCategory::PHI);
        assert!(pack.is_ok(), "PHI pack should load");
        let pack = pack.unwrap();
        assert_eq!(pack.category, RulePackCategory::PHI);
    }

    #[test]
    fn test_load_mnpi_pack() {
        let loader = Loader::new();
        let pack = loader.load_pack(RulePackCategory::MNPI);
        assert!(pack.is_ok(), "MNPI pack should load");
        let pack = pack.unwrap();
        assert_eq!(pack.category, RulePackCategory::MNPI);
    }

    #[test]
    fn test_load_all_packs() {
        let loader = Loader::new();
        let packs = loader.load_all();
        assert!(packs.is_ok(), "all packs should load");
        let packs = packs.unwrap();
        assert_eq!(packs.len(), 3);
    }

    #[test]
    fn test_pack_categories_are_correct() {
        let loader = Loader::new();
        let packs = loader.load_all().unwrap();

        let categories: Vec<RulePackCategory> = packs.iter().map(|p| p.category).collect();

        assert!(categories.contains(&RulePackCategory::Privilege));
        assert!(categories.contains(&RulePackCategory::PHI));
        assert!(categories.contains(&RulePackCategory::MNPI));
    }

    #[test]
    fn test_pack_has_precedence_group() {
        let loader = Loader::new();
        let packs = loader.load_all().unwrap();

        for pack in packs {
            assert!(
                !pack.precedence_group.is_empty(),
                "each pack must have a precedence group"
            );
        }
    }

    #[test]
    fn test_pack_has_entities() {
        let loader = Loader::new();
        let packs = loader.load_all().unwrap();

        for pack in packs {
            assert!(
                !pack.entities.is_empty(),
                "each pack must have at least one entity type"
            );
        }
    }
}
