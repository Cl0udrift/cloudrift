package schema

type QueryRequest struct {
	Query       string `json:"query"`
	ScanID      string `json:"scan_id,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	ModeHint    string `json:"mode_hint,omitempty"`
	TopK        int    `json:"top_k,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	EntityID    string `json:"entity_id,omitempty"`
	PrincipalID string `json:"principal_id,omitempty"`
}

type QuerySupportingFact struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type QueryRelatedObject struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	URL   string `json:"url,omitempty"`
}

type QueryResponse struct {
	Answer              string                `json:"answer"`
	AnswerType          string                `json:"answer_type"`
	Intent              string                `json:"intent"`
	Confidence          string                `json:"confidence"`
	SupportLevel        string                `json:"support_level"`
	ScanID              string                `json:"scan_id,omitempty"`
	GraphUsed           bool                  `json:"graph_used"`
	SemanticUsed        bool                  `json:"semantic_used"`
	DomainUsed          bool                  `json:"domain_used"`
	SupportingFacts     []QuerySupportingFact `json:"supporting_facts"`
	RelatedObjects      []QueryRelatedObject  `json:"related_objects"`
	RecommendedActions  []string              `json:"recommended_actions,omitempty"`
	FollowUpSuggestions []string              `json:"follow_up_suggestions,omitempty"`
	Notes               []string              `json:"notes,omitempty"`
}
