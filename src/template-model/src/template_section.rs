use serde::{Deserialize, Serialize};

/// A top-level CloudFormation template section, as documented in the template
/// anatomy (<https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html>).
///
/// This is the canonical, single definition of the section names - section
/// constants in other crates derive from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum TopLevelSection {
    Resources,
    Parameters,
    Outputs,
    Mappings,
    Metadata,
    Rules,
    Conditions,
    Transform,
    FormatVersion,
    Description,
}

impl TopLevelSection {
    const ALL: [TopLevelSection; 10] = [
        TopLevelSection::Resources,
        TopLevelSection::Parameters,
        TopLevelSection::Outputs,
        TopLevelSection::Mappings,
        TopLevelSection::Metadata,
        TopLevelSection::Rules,
        TopLevelSection::Conditions,
        TopLevelSection::Transform,
        TopLevelSection::FormatVersion,
        TopLevelSection::Description,
    ];

    /// The section's key as written in a template.
    pub const fn name(self) -> &'static str {
        match self {
            TopLevelSection::Resources => "Resources",
            TopLevelSection::Parameters => "Parameters",
            TopLevelSection::Outputs => "Outputs",
            TopLevelSection::Mappings => "Mappings",
            TopLevelSection::Metadata => "Metadata",
            TopLevelSection::Rules => "Rules",
            TopLevelSection::Conditions => "Conditions",
            TopLevelSection::Transform => "Transform",
            TopLevelSection::FormatVersion => "AWSTemplateFormatVersion",
            TopLevelSection::Description => "Description",
        }
    }

    /// Parses a template key into its section - the inverse of [`Self::name`].
    pub fn from_name(name: &str) -> Option<TopLevelSection> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    /// The entity type of this section's children.
    pub const fn entity_type(self) -> EntityType {
        match self {
            TopLevelSection::Resources => EntityType::Resource,
            TopLevelSection::Parameters => EntityType::Parameter,
            TopLevelSection::Outputs => EntityType::Output,
            TopLevelSection::Mappings => EntityType::Mapping,
            TopLevelSection::Metadata => EntityType::Metadata,
            TopLevelSection::Rules => EntityType::Rule,
            TopLevelSection::Conditions => EntityType::Condition,
            TopLevelSection::Transform => EntityType::Transform,
            TopLevelSection::FormatVersion => EntityType::FormatVersion,
            TopLevelSection::Description => EntityType::Description,
        }
    }
}

/// The kind of template entity a diagnostic targets - the singular form of the
/// top-level section the entity is declared in. Every documented section has a
/// variant; the ones whose children are addressable by logical ID (resources,
/// parameters, outputs, mappings, conditions, rules, and metadata keys) are
/// the ones diagnostics attribute findings to today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum EntityType {
    Resource,
    Parameter,
    Output,
    Mapping,
    Metadata,
    Rule,
    Condition,
    Transform,
    FormatVersion,
    Description,
}

impl EntityType {
    const ALL: [EntityType; 10] = [
        EntityType::Resource,
        EntityType::Parameter,
        EntityType::Output,
        EntityType::Mapping,
        EntityType::Metadata,
        EntityType::Rule,
        EntityType::Condition,
        EntityType::Transform,
        EntityType::FormatVersion,
        EntityType::Description,
    ];

    /// The entity type's name - the singular form used in serialized
    /// diagnostics and filter configurations.
    pub const fn name(self) -> &'static str {
        match self {
            EntityType::Resource => "Resource",
            EntityType::Parameter => "Parameter",
            EntityType::Output => "Output",
            EntityType::Mapping => "Mapping",
            EntityType::Metadata => "Metadata",
            EntityType::Rule => "Rule",
            EntityType::Condition => "Condition",
            EntityType::Transform => "Transform",
            EntityType::FormatVersion => "FormatVersion",
            EntityType::Description => "Description",
        }
    }

    /// The top-level template section this kind of entity is declared in.
    pub const fn section(self) -> TopLevelSection {
        match self {
            EntityType::Resource => TopLevelSection::Resources,
            EntityType::Parameter => TopLevelSection::Parameters,
            EntityType::Output => TopLevelSection::Outputs,
            EntityType::Mapping => TopLevelSection::Mappings,
            EntityType::Metadata => TopLevelSection::Metadata,
            EntityType::Rule => TopLevelSection::Rules,
            EntityType::Condition => TopLevelSection::Conditions,
            EntityType::Transform => TopLevelSection::Transform,
            EntityType::FormatVersion => TopLevelSection::FormatVersion,
            EntityType::Description => TopLevelSection::Description,
        }
    }

    /// Maps a top-level template section name to the entity type of its
    /// children. Returns `None` for keys that are not documented sections.
    pub fn from_section(section: &str) -> Option<EntityType> {
        TopLevelSection::from_name(section).map(TopLevelSection::entity_type)
    }
}

impl std::str::FromStr for EntityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|entity_type| entity_type.name().eq_ignore_ascii_case(s)).ok_or_else(|| {
            format!("Invalid entity type '{s}'; expected one of: {}", Self::ALL.map(EntityType::name).join(", "))
        })
    }
}

/// Splits a section-absolute, slash-separated template path (such as
/// `Parameters/MyParam/Type` or `Outputs/MyOutput/Value`) into the entity type
/// of the section's children and the logical ID of the entity it addresses.
/// Returns `None` for paths that are not rooted at a documented top-level
/// section - resource-relative dotted paths like `Properties.BucketName` - or
/// that name a section with no child segment.
pub fn entity_identity(path: &str) -> Option<(EntityType, &str)> {
    let mut segments = path.split('/');
    let entity_type = EntityType::from_section(segments.next()?)?;
    let logical_id = segments.next().filter(|id| !id.is_empty())?;
    Some((entity_type, logical_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_names_round_trip_through_from_name() {
        for section in TopLevelSection::ALL {
            assert_eq!(TopLevelSection::from_name(section.name()), Some(section), "{section:?}");
        }
        assert_eq!(TopLevelSection::from_name("Globals"), None, "SAM Globals is not a documented section");
        assert_eq!(TopLevelSection::from_name("Constants"), None);
        assert_eq!(TopLevelSection::from_name(""), None);
    }

    #[test]
    fn format_version_uses_the_full_template_key() {
        assert_eq!(TopLevelSection::FormatVersion.name(), "AWSTemplateFormatVersion");
        assert_eq!(TopLevelSection::from_name("AWSTemplateFormatVersion"), Some(TopLevelSection::FormatVersion));
    }

    #[test]
    fn entity_type_and_section_are_inverse_mappings() {
        for section in TopLevelSection::ALL {
            assert_eq!(section.entity_type().section(), section, "{section:?}");
        }
    }

    #[test]
    fn from_section_maps_names_to_singular_entity_types() {
        assert_eq!(EntityType::from_section("Resources"), Some(EntityType::Resource));
        assert_eq!(EntityType::from_section("Parameters"), Some(EntityType::Parameter));
        assert_eq!(EntityType::from_section("Outputs"), Some(EntityType::Output));
        assert_eq!(EntityType::from_section("Mappings"), Some(EntityType::Mapping));
        assert_eq!(EntityType::from_section("Conditions"), Some(EntityType::Condition));
        assert_eq!(EntityType::from_section("Rules"), Some(EntityType::Rule));
        assert_eq!(EntityType::from_section("Metadata"), Some(EntityType::Metadata));
        assert_eq!(EntityType::from_section("Transform"), Some(EntityType::Transform));
        assert_eq!(EntityType::from_section("AWSTemplateFormatVersion"), Some(EntityType::FormatVersion));
        assert_eq!(EntityType::from_section("Description"), Some(EntityType::Description));
        assert_eq!(EntityType::from_section("Resource"), None, "singular form is not a section name");
    }

    #[test]
    fn entity_identity_splits_section_absolute_paths() {
        assert_eq!(entity_identity("Parameters/MyParam/Type"), Some((EntityType::Parameter, "MyParam")));
        assert_eq!(entity_identity("Parameters/MyParam"), Some((EntityType::Parameter, "MyParam")));
        assert_eq!(entity_identity("Outputs/MyOutput/Value"), Some((EntityType::Output, "MyOutput")));
        assert_eq!(entity_identity("Mappings/MyMap/Key1/Key2"), Some((EntityType::Mapping, "MyMap")));
        assert_eq!(entity_identity("Conditions/IsProd"), Some((EntityType::Condition, "IsProd")));
        assert_eq!(entity_identity("Rules/MyRule/Assertions/0"), Some((EntityType::Rule, "MyRule")));
        assert_eq!(entity_identity("Resources/MyBucket/Properties/Name"), Some((EntityType::Resource, "MyBucket")));
    }

    #[test]
    fn entity_identity_handles_mixed_dot_segments_after_the_entity() {
        // Builder-style paths mix slash and dot separators past the entity;
        // only the first two slash segments matter for identity.
        assert_eq!(entity_identity("Outputs/X/Value.Fn::If.1"), Some((EntityType::Output, "X")));
    }

    #[test]
    fn entity_identity_rejects_non_entity_paths() {
        assert_eq!(entity_identity("Properties.BucketName"), None, "resource-relative dotted path");
        assert_eq!(entity_identity("Parameters"), None, "bare section has no entity");
        assert_eq!(entity_identity("Description"), None, "bare section has no entity");
        assert_eq!(entity_identity("AWSTemplateFormatVersion"), None, "bare section has no entity");
        assert_eq!(entity_identity("Globals/Function"), None, "SAM Globals is not a documented section");
        assert_eq!(entity_identity(""), None);
        assert_eq!(entity_identity("Parameters//Type"), None, "empty entity segment");
    }
}
