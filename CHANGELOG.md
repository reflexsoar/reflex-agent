# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Opensearch input plugin

## 21.11.0 - 2021-11-05

### Enhancement

- Added agent logic for parsing tags from any source field and adding it to the event based on the fields designated in `tag_fields` on the input config
- Added agent logic for parsing event signatures based on a set of signature fields in the `signature_fields` list in the input config
- Moved Event signature generation to the Agent
- Agent now supports field aliases as defined in `field_mappings`.  Field aliases will take the place of `source_field` for use in the management console for writing RQL
- Added new configuration field for Elasticsearch inputs called `lucene_filter` to allow for more granular targeting of data in the source index

### Bug

- Improved the get_nested_field() function on Event so that it accounts for dot notation field names