# CLAUDE.md - Display Implementation Guide

This file provides guidance for implementing display functionality for new types from `certs-types`.

## Overview

The `certs-display` crate provides display implementations for types in `certs-types` using the `Repr` trait. This trait defines two methods:
- `text()`: Returns a pretty-printed UI element using iocraft
- `json()`: Returns a JSON representation of the data

## Implementation Process

### 1. Examine the Target Type

First, examine the type in `certs-types` to understand its structure:

```rust
// Example from certs-types/src/subject.rs
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject {
    pub common_name: Option<Arc<str>>,
    pub organization: Option<Arc<str>>,
    pub organization_unit: Option<Arc<str>>,
    pub country: Option<Arc<str>>,
    pub state: Option<Arc<str>>,
}
```

### 2. Create Implementation File

Create a new file in `src/impls/` named after your type (e.g., `subject.rs`):

```rust
use certs_types::subject::Subject;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Subject {
    // Implementation here
}
```

### 3. Implement the `text()` Method

The `text()` method should return a pretty-printed UI element using iocraft. Key patterns:

- Use `element!` macro for declarative UI composition
- Use `View` for containers and `Text` for content
- Use `Color::Green` for field labels (following existing conventions)
- Handle optional fields gracefully
- Return `AnyElement<'static>` wrapped with `.into_any()`

```rust
fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
    let mut components = Vec::new();

    // Add components for each field
    if let Some(field_value) = &self.field_name {
        components.push(element! { View {
            Text(content: "field_label: ", color: Color::Green)
            Text(content: field_value.as_ref())
        }});
    }

    Ok(element! { View {
        Text(content: "type_name: ", color: Color::Green)
        #(components)
    }}
    .into_any())
}
```

### 4. Implement the `json()` Method

The `json()` method should return a JSON representation:

- Create a `serde_json::Map` for object types
- Only include fields that have values (omit `None` fields)
- Use appropriate field names (often abbreviated for X.509 fields)
- Return `serde_json::Value`

```rust
fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();

    if let Some(field_value) = &self.field_name {
        obj.insert("field_key".to_string(), 
                   serde_json::Value::String(field_value.as_ref().to_string()));
    }

    Ok(serde_json::Value::Object(obj))
}
```

### 5. Add Tests

Include comprehensive tests covering:
- Full data (all fields populated)
- Empty data (no fields populated)
- Partial data (some fields populated)

```rust
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use iocraft::ElementExt;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_full_data() {
        let instance = YourType {
            field: Some(Arc::from("test_value")),
        };

        // Test text output
        let mut element = instance.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("expected_content"));

        // Test JSON output
        let json = instance.json(&Config::default()).unwrap();
        let expected = json!({"field_key": "test_value"});
        assert_eq!(json, expected);
    }

    #[test]
    fn test_empty_data() {
        let instance = YourType {
            field: None,
        };

        let json = instance.json(&Config::default()).unwrap();
        assert_eq!(json, json!({}));
    }
}
```

### 6. Update Module Declaration

Add your new module to `src/impls/mod.rs`:

```rust
mod your_type;
```

### 7. Run Tests

Verify your implementation:

```bash
cargo test -p certs-display
```

## Design Patterns

### Field Naming Conventions

- Use standard X.509 abbreviations when applicable:
  - `cn` for Common Name
  - `o` for Organization
  - `ou` for Organizational Unit
  - `c` for Country
  - `st` for State/Province

### Color Usage

- Use `Color::Green` for field labels
- Use default color for field values
- Be consistent with existing implementations

### Handling Optional Fields

- For text output: Only display fields that have values
- For JSON output: Only include fields that have values in the object
- Handle empty objects/displays gracefully

### Complex Data Structures

For arrays or complex nested structures, see `sans.rs` for examples:

```rust
// For arrays
if !self.dns.is_empty() {
    obj.insert(
        "dns".to_string(),
        serde_json::Value::Array(
            self.dns
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
}
```

## Testing Your Implementation

1. Run the specific crate tests: `cargo test -p certs-display`
2. Test with actual certificate data if available
3. Verify both JSON and text outputs are correctly formatted
4. Test edge cases (empty data, partial data, full data)
5. Run workspace check to ensure no compilation errors: `cargo check --workspace`

## Committing Your Changes

After implementing and testing your `Repr` implementation:

1. **Stage your changes**:
   ```bash
   git add certs-display/src/impls/your_type.rs
   git add certs-display/src/impls/mod.rs
   ```

2. **Create a descriptive commit**:
   ```bash
   git commit -m "$(cat <<'EOF'
   Add Repr implementation for YourType struct

   Implement display formatting for [brief description]:
   - Add text() method with appropriate label and field formatting
   - Add json() method with standard field abbreviations
   - Include comprehensive tests for full, empty, and partial data scenarios
   - Follow existing patterns from similar implementations

   🤖 Generated with [Claude Code](https://claude.ai/code)

   Co-Authored-By: Claude <noreply@anthropic.com>
   EOF
   )"
   ```

3. **Verify the commit**:
   ```bash
   git status
   git log --oneline -1
   ```

## Integration

Once implemented, the display functionality will be automatically available wherever the `Repr` trait is used in the codebase. The CLI will use these implementations for formatted output.