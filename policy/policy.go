// Package policy provides the methods and data structures needed to parse and
// create IAM policy documents
package policy

import (
	"encoding/json"
	"fmt"
)

// PolicyVersion unmarshaling error when an invalid policy document version is
// used
type InvalidPolicyVersionError string

// Version returns the invalid version string used in the document
func (s InvalidPolicyVersionError) Version() string {
	return string(s)
}

func (s InvalidPolicyVersionError) Error() string {
	return fmt.Sprintf("Invalid Policy Version %s", string(s))
}

// Effect unmarshaling error when an invalid Effect is used
type InvalidEffectError string

func (s InvalidEffectError) Error() string {
	return fmt.Sprintf("Invalid Effect %s", string(s))
}

// PolicyVersion represents the version of an IAM policy document. It will
// always be "2012-10-17". A document using the older "2008-10-17" version
// will automatically by 'upgraded'
type PolicyVersion struct{}

// MarshalJSON implements the json.Marshaler interface.
func (_ PolicyVersion) MarshalJSON() ([]byte, error) {
	return ([]byte)(`"2012-10-17"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (_ PolicyVersion) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == `"2012-10-17"` || s == `"2008-10-17"` {
		return nil
	}
	return InvalidPolicyVersionError(s)
}

const (
	Allow Effect = true
	Deny  Effect = false
)

// The Effect indicates whether you want the statement to result in an allow
// or an explicit deny
type Effect bool

// MarshalJSON implements the json.Marshaler interface.
func (e Effect) MarshalJSON() ([]byte, error) {
	if bool(e) {
		return []byte(`"Allow"`), nil
	} else {
		return []byte(`"Deny"`), nil
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (e *Effect) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == `"Allow"` {
		*e = true
		return nil
	}
	if s == `"Deny"` {
		*e = false
		return nil
	}
	return InvalidEffectError(s)
}

// The person or persons who receive or are denied permission according to the
// policy
type Principal struct {
	Aws []string `json:"AWS"`
}

func NewPrincipal() *Principal {
	return &Principal{
		make([]string, 0),
	}
}

// ConditionType represents all the possible comparison types for the
// Condition of a Policy Statement
type ConditionType string

const (
	ConditionStringEquals              ConditionType = "StringEquals"
	ConditionStringNotEquals           ConditionType = "StringNotEquals"
	ConditionStringEqualsIgnoreCase    ConditionType = "StringEqualsIgnoreCase"
	ConditionStringNotEqualsIgnoreCase ConditionType = "StringNotEqualsIgnoreCase"
	ConditionStringLike                ConditionType = "StringLike"
	ConditionStringNotLike             ConditionType = "StringNotLike"
	ConditionNumericEquals             ConditionType = "NumericEquals"
	ConditionNumericNotEquals          ConditionType = "NumericNotEquals"
	ConditionNumericLessThan           ConditionType = "NumericLessThan"
	ConditionNumericLessThanEquals     ConditionType = "NumericLessThanEquals"
	ConditionNumericGreaterThan        ConditionType = "NumericGreaterThan"
	ConditionNumericGreaterThanEquals  ConditionType = "NumericGreaterThanEquals"
	ConditionDateEquals                ConditionType = "DateEquals"
	ConditionDateNotEquals             ConditionType = "DateNotEquals"
	ConditionDateLessThan              ConditionType = "DateLessThan"
	ConditionDateLessThanEquals        ConditionType = "DateLessThanEquals"
	ConditionDateGreaterThan           ConditionType = "DateGreaterThan"
	ConditionDateGreaterThanEquals     ConditionType = "DateGreaterThanEquals"
	ConditionBool                      ConditionType = "Bool"
	ConditionIpAddress                 ConditionType = "IpAddress"
	ConditionNotIpAddress              ConditionType = "NotIpAddress"
	ConditionArnEquals                 ConditionType = "ArnEquals"
	ConditionArnNotEquals              ConditionType = "ArnNotEquals"
	ConditionArnLike                   ConditionType = "ArnLike"
	ConditionArnNotLike                ConditionType = "ArnNotLike"
	ConditionNull                      ConditionType = "Null"
)

// ConditionVariable represent the available variables used in Conditions
type ConditionVariable string

const (
	VarCurrentTime        ConditionVariable = "aws:CurrentTime"
	VarEpochTime          ConditionVariable = "aws:EpochTime"
	VarMultiFactorAuthAge ConditionVariable = "aws:MultiFactorAuthAge"
	VarPrincipalType      ConditionVariable = "aws:principaltype"
	VarSecureTransport    ConditionVariable = "aws:SecureTransport"
	VarSourceArn          ConditionVariable = "aws:SourceArn"
	VarSourceIp           ConditionVariable = "aws:SourceIp"
	VarUserAgent          ConditionVariable = "aws:UserAgent"
	VarUsedId             ConditionVariable = "aws:userid"
	VarUsername           ConditionVariable = "aws:username"
)

// The main element of a single Policy Statement
type Statement struct {
	Sid          *string `json:",omitempty"`
	Effect       Effect
	Principal    *Principal
	NotPrincipal *Principal `json:",omitempty"`
	Action       []string
	NotAction    []string `json:",omitempty"`
	Resource     string
	Condition    map[ConditionType]map[ConditionVariable][]string `json:",omitempty"`
}

// Set the Statement's Sid
func (s *Statement) SetSid(id string) {
	s.Sid = &id
}

// Add an extra person to the Principal list
func (s *Statement) AddPrincipal(p string) {
	s.Principal.Aws = append(s.Principal.Aws, p)
}

// Add an extra person to the NotPrincipal list
func (s *Statement) AddNotPrincipal(p string) {
	if s.NotPrincipal == nil {
		s.NotPrincipal = NewPrincipal()
	}
	s.NotPrincipal.Aws = append(s.NotPrincipal.Aws, p)
}

// Add an Action
func (s *Statement) AddAction(a string) {
	s.Action = append(s.Action, a)
}

// Add a NotAction
func (s *Statement) AddNotAction(a string) {
	s.NotAction = append(s.NotAction, a)
}

// Add a Condition to the statement
func (s *Statement) AddCondition(t ConditionType, key ConditionVariable, value string) {
	if _, ok := s.Condition[t]; !ok {
		s.Condition[t] = make(map[ConditionVariable][]string)
	}
	if _, ok := s.Condition[t][key]; !ok {
		s.Condition[t][key] = make([]string, 0, 1)
	}
	s.Condition[t][key] = append(s.Condition[t][key], value)
}

// Policy is a complete IAM Policy document
type Policy struct {
	Version   PolicyVersion
	Id        *string `json:",omitempty"`
	Statement []*Statement
}

// Create a new empty Policy
func NewPolicy() *Policy {
	return &Policy{Statement: make([]*Statement, 0, 1)}
}

// Create a policy from JSON
func LoadPolicy(b []byte) (*Policy, error) {
	p := Policy{}
	err := json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Set the Id of a policy
func (p *Policy) SetId(id string) {
	p.Id = &id
}

// Add a new (empty) Statement to the Policy, returns the new Statement
func (p *Policy) AddStatement() *Statement {
	statement := &Statement{
		Principal: NewPrincipal(),
		Action:    make([]string, 0, 1),
		Condition: make(map[ConditionType]map[ConditionVariable][]string),
	}
	p.Statement = append(p.Statement, statement)
	return statement
}

// Retrieve the policy as a JSON encoded string, ready for use in AWS API calls
func (p *Policy) Get() ([]byte, error) {
	result, err := json.Marshal(p)
	return result, err
}

// Retrieve the policy as a formatted JSON encoded string
func (p *Policy) String() string {
	result, _ := json.MarshalIndent(p, "", "    ")
	return string(result)
}
