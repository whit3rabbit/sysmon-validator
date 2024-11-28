#[derive(Debug)]
pub struct SysmonConfig {
    pub schema_version: Option<String>,
    pub event_filtering: Option<EventFiltering>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Condition {
    pub operator: Option<String>,
    pub value: String,
}

#[derive(Debug)]
pub struct EventFiltering {
    pub rule_groups: Vec<RuleGroup>,
}

#[derive(Debug)]
pub struct RuleGroup {
    pub name: Option<String>,
    pub group_relation: Option<String>,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct Event {
    pub event_type: String,
    pub onmatch: Option<String>,
    pub fields: Vec<Field>,
}

#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub condition: Option<String>,
    pub value: String,
}