//
// Copyright (c) 2013 Gijs Kunze
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
//

package policy

import (
	"encoding/json"
	"testing"
)

func assertPolicy(t *testing.T, p *Policy, expected string) {
	data, err := p.Get()
	if err != nil {
		t.Error(err)
		return
	}
	got := string(data)

	if got != expected {
		t.Errorf("Expected \n%s got \n%s", expected, got)
	}
}

func TestPolicyVersionMarshal(t *testing.T) {
	v := PolicyVersion{}
	expected := `"2012-10-17"`

	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Failed marshaling policy version: %s", err.Error())
	}

	if expected != string(got) {
		t.Errorf("Expected %s got %s", expected, string(got))
	}
}

func TestPolicyVersionUnmarshal(t *testing.T) {
	v := PolicyVersion{}
	data := []byte(`"2012-10-17"`)

	err := json.Unmarshal(data, &v)

	if err != nil {
		t.Errorf("Failed unmarhshaling %s", err.Error())
	}

	data = []byte(`"2008-10-17"`)

	err = json.Unmarshal(data, &v)

	if err != nil {
		t.Errorf("Failed unmarhshaling %s", err.Error())
	}

	data = []byte(`"2009-10-17"`)

	err = json.Unmarshal(data, &v)
	if _, ok := err.(InvalidPolicyVersionError); err == nil || !ok {
		t.Error("No error unmarshaling invalid version, expected InvalidPolicyVersionError")
	}
}

func TestEffectMarshal(t *testing.T) {
	expected := `"Allow"`

	got, err := json.Marshal(Allow)
	if err != nil {
		t.Fatalf("Failed marshaling effect: %s", err.Error())
	}

	if expected != string(got) {
		t.Errorf("Expected %s got %s", expected, string(got))
	}

	expected = `"Deny"`

	got, err = json.Marshal(Deny)
	if err != nil {
		t.Fatalf("Failed marshaling effect: %s", err.Error())
	}

	if expected != string(got) {
		t.Errorf("Expected %s got %s", expected, string(got))
	}
}

func TestEffectUnmarshal(t *testing.T) {
	var e Effect

	allow, deny := []byte(`"Allow"`), []byte(`"Deny"`)

	err := json.Unmarshal(allow, &e)
	if err != nil {
		t.Errorf("Failed unmarshaling effect %s", err)
	}
	if e != Allow {
		t.Errorf("Expected %v got %v", Allow, e)
	}

	err = json.Unmarshal(deny, &e)
	if err != nil {
		t.Errorf("Failed unmarshaling effect %s", err)
	}
	if e != Deny {
		t.Errorf("Expected %v got %v", Deny, e)
	}
}

func TestEmptyPolicy(t *testing.T) {
	p := NewPolicy()
	expected := `{"Version":"2012-10-17","Statement":[]}`

	assertPolicy(t, p, expected)
}

func TestEmptyStatement(t *testing.T) {
	p := NewPolicy()
	p.AddStatement()
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":[]},"Action":[],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestAllowStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.Effect = Allow
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[]},"Action":[],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestPrincipalStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.AddPrincipal("*")
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":["*"]},"Action":[],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestNotPrincipalStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.AddNotPrincipal("*")
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":[]},"NotPrincipal":{"AWS":["*"]},"Action":[],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestActionStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.AddAction("*")
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":[]},"Action":["*"],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestNotActionStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.AddNotAction("*")
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":[]},"Action":[],"NotAction":["*"],"Resource":""}]}`

	assertPolicy(t, p, expected)
}

func TestConditionStatement(t *testing.T) {
	p := NewPolicy()
	stmt := p.AddStatement()
	stmt.AddCondition("ArnEquals", "aws:SourceArn", "arn:sns:foo")
	expected := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":[]},"Action":[],"Resource":"","Condition":{"ArnEquals":{"aws:SourceArn":["arn:sns:foo"]}}}]}`

	assertPolicy(t, p, expected)
}
