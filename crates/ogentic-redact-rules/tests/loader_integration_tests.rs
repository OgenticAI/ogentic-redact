use ogentic_redact_rules::{Loader, RulePackCategory};

#[test]
fn test_privilege_pack_loads_and_validates() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::Privilege);

    assert!(pack.is_ok(), "privilege pack must load without error");

    let pack = pack.unwrap();
    assert_eq!(pack.category, RulePackCategory::Privilege);
    assert!(!pack.precedence_group.is_empty(), "privilege pack must have precedence group");
    assert!(!pack.entities.is_empty(), "privilege pack must have entity definitions");

    for entity in &pack.entities {
        assert!(
            !entity.entity_type.is_empty(),
            "entity type must not be empty"
        );
        assert!(
            !entity.patterns.is_empty() || !entity.recognizers.is_empty(),
            "entity must have patterns or recognizers"
        );

        for pattern in &entity.patterns {
            assert!(
                !pattern.regex.is_empty(),
                "pattern regex must not be empty"
            );
        }
    }
}

#[test]
fn test_phi_pack_loads_and_validates() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::PHI);

    assert!(pack.is_ok(), "PHI pack must load without error");

    let pack = pack.unwrap();
    assert_eq!(pack.category, RulePackCategory::PHI);
    assert!(!pack.precedence_group.is_empty(), "PHI pack must have precedence group");
    assert!(!pack.entities.is_empty(), "PHI pack must have entity definitions");

    let diagnosis_exists = pack.entities.iter().any(|e| {
        e.entity_type.to_uppercase().contains("DIAGNOSIS")
    });
    assert!(
        diagnosis_exists,
        "PHI pack must contain diagnosis entity"
    );

    let treatment_exists = pack.entities.iter().any(|e| {
        e.entity_type.to_uppercase().contains("TREATMENT")
    });
    assert!(
        treatment_exists,
        "PHI pack must contain treatment entity"
    );
}

#[test]
fn test_mnpi_pack_loads_and_validates() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::MNPI);

    assert!(pack.is_ok(), "MNPI pack must load without error");

    let pack = pack.unwrap();
    assert_eq!(pack.category, RulePackCategory::MNPI);
    assert!(
        !pack.precedence_group.is_empty(),
        "MNPI pack must have precedence group"
    );
    assert!(
        !pack.entities.is_empty(),
        "MNPI pack must have entity definitions"
    );

    let earnings_exists = pack.entities.iter().any(|e| {
        e.entity_type.to_uppercase().contains("EARNINGS")
    });
    assert!(
        earnings_exists,
        "MNPI pack must contain earnings guidance entity"
    );
}

#[test]
fn test_all_packs_have_unique_precedence_groups() {
    let loader = Loader::new();
    let packs = loader.load_all().expect("all packs must load");

    let mut precedence_groups: Vec<String> = packs
        .iter()
        .map(|p| p.precedence_group.clone())
        .collect();

    precedence_groups.sort();
    let original_len = precedence_groups.len();
    precedence_groups.dedup();

    assert_eq!(
        original_len,
        precedence_groups.len(),
        "each pack must have a unique precedence group"
    );
}

#[test]
fn test_pack_entity_types_are_unique_within_pack() {
    let loader = Loader::new();
    let packs = loader.load_all().expect("all packs must load");

    for pack in packs {
        let mut entity_types: Vec<String> =
            pack.entities.iter().map(|e| e.entity_type.clone()).collect();

        let original_len = entity_types.len();
        entity_types.sort();
        entity_types.dedup();

        assert_eq!(
            original_len,
            entity_types.len(),
            "{} pack entity types must be unique",
            pack.category
        );
    }
}

#[test]
fn test_patterns_compile_as_valid_regex() {
    let loader = Loader::new();
    let packs = loader.load_all().expect("all packs must load");

    for pack in packs {
        assert!(
            pack.validate().is_ok(),
            "{} pack patterns must compile as valid regex",
            pack.category
        );
    }
}

#[test]
fn test_privilege_pack_detects_attorney_client_phrases() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::Privilege).unwrap();

    let attorney_client_entity = pack
        .entities
        .iter()
        .find(|e| e.entity_type.contains("ATTORNEY_CLIENT"))
        .expect("privilege pack must have attorney-client privilege entity");

    assert!(
        !attorney_client_entity.patterns.is_empty(),
        "attorney-client entity must have patterns"
    );

    let patterns = attorney_client_entity
        .patterns
        .iter()
        .map(|p| &p.regex)
        .collect::<Vec<_>>();

    let attorney_client_pattern = patterns
        .iter()
        .any(|p| p.contains("attorney") && p.contains("client"));

    assert!(
        attorney_client_pattern,
        "privilege pack must have pattern matching attorney-client"
    );
}

#[test]
fn test_phi_pack_has_medical_entities() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::PHI).unwrap();

    let entity_types: Vec<&str> = pack
        .entities
        .iter()
        .map(|e| e.entity_type.as_str())
        .collect();

    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("DIAGNOSIS")),
        "PHI pack must have diagnosis entity"
    );
    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("TREATMENT")),
        "PHI pack must have treatment entity"
    );
    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("MEDICATION") || t.to_uppercase().contains("PRESCRIPTION")),
        "PHI pack must have medication/prescription entity"
    );
}

#[test]
fn test_mnpi_pack_has_financial_entities() {
    let loader = Loader::new();
    let pack = loader.load_pack(RulePackCategory::MNPI).unwrap();

    let entity_types: Vec<&str> = pack
        .entities
        .iter()
        .map(|e| e.entity_type.as_str())
        .collect();

    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("EARNINGS")),
        "MNPI pack must have earnings entity"
    );
    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("FINANCIAL")),
        "MNPI pack must have financial entity"
    );
    assert!(
        entity_types
            .iter()
            .any(|t| t.to_uppercase().contains("ACQUISITION") || t.to_uppercase().contains("M&A")),
        "MNPI pack must have acquisition/M&A entity"
    );
}

#[test]
fn test_recognizers_are_valid_builtin_types() {
    let loader = Loader::new();
    let packs = loader.load_all().expect("all packs must load");

    let valid_types = vec!["builtin", "custom"];

    for pack in packs {
        for entity in &pack.entities {
            for recognizer in &entity.recognizers {
                assert!(
                    valid_types.contains(&recognizer.recognizer_type.as_str()),
                    "recognizer type must be 'builtin' or 'custom', got '{}'",
                    recognizer.recognizer_type
                );

                assert!(
                    !recognizer.name.is_empty(),
                    "recognizer name must not be empty"
                );
            }
        }
    }
}
