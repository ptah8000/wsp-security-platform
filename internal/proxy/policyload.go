package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/store"
)

// LoadEngineFromStore lists policies/objects from the database, compiles them,
// and returns a ready Engine. Empty policy set yields an engine with default allow.
func LoadEngineFromStore(ctx context.Context, s *store.Store) (*policy.Engine, error) {
	if s == nil {
		return nil, fmt.Errorf("store is nil")
	}
	rows, err := s.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	objs, err := s.ListReusableObjects(ctx)
	if err != nil {
		return nil, err
	}

	rules := make([]policy.Rule, 0, len(rows))
	for _, row := range rows {
		var sections policy.RuleSections
		if len(row.Sections) > 0 {
			if err := json.Unmarshal(row.Sections, &sections); err != nil {
				return nil, fmt.Errorf("policy %s sections: %w", row.ID, err)
			}
		}
		rules = append(rules, policy.Rule{
			ID:          row.ID,
			Name:        row.Name,
			Description: row.Description,
			Enabled:     row.Enabled,
			Priority:    row.Priority,
			Sections:    sections,
		})
	}

	objectMap := make(map[uuid.UUID]policy.Object, len(objs))
	for _, o := range objs {
		var def policy.ObjectDefinition
		if len(o.Definition) > 0 {
			if err := json.Unmarshal(o.Definition, &def); err != nil {
				return nil, fmt.Errorf("object %s definition: %w", o.ID, err)
			}
		}
		objectMap[o.ID] = policy.Object{
			ID:         o.ID,
			Name:       o.Name,
			Type:       o.Type,
			Definition: def,
			IsSystem:   o.IsSystem,
		}
	}

	snap, err := policy.Compile(rules, objectMap)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	eng := &policy.Engine{}
	eng.Swap(snap)
	return eng, nil
}
