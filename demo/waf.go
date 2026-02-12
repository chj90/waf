package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WAFRule defines a single detection rule
type WAFRule struct {
	Name        string
	Category    string
	Patterns    []*regexp.Regexp
	Description string
	Severity    string // "HIGH", "MEDIUM", "LOW"
}

// WAFResult represents the result of WAF inspection
type WAFResult struct {
	Blocked     bool   `json:"blocked"`
	RuleName    string `json:"ruleName"`
	Category    string `json:"category"`
	MatchedPart string `json:"matchedPart"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// WAFLog represents a single WAF event log entry
type WAFLog struct {
	Timestamp string    `json:"timestamp"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Input     string    `json:"input"`
	Result    WAFResult `json:"result"`
	ClientIP  string    `json:"clientIP"`
}

// WAFEngine is the core WAF engine
type WAFEngine struct {
	mu      sync.RWMutex
	enabled bool
	rules   []WAFRule
	logs    []WAFLog
}

// NewWAFEngine creates and initializes a WAF engine with all rules
func NewWAFEngine() *WAFEngine {
	engine := &WAFEngine{
		enabled: true,
		logs:    make([]WAFLog, 0),
	}
	engine.loadRules()
	return engine
}

func (w *WAFEngine) loadRules() {
	w.rules = []WAFRule{
		// SQL Injection Rules
		{
			Name:     "SQLi-001",
			Category: "SQL Injection",
			Patterns: compilePatterns(
				`(?i)('\s*(OR|AND)\s+'?\d*'?\s*=\s*'?\d*'?)`,            // ' OR '1'='1'
				`(?i)('\s*(OR|AND)\s+\d+\s*=\s*\d+)`,                   // ' OR 1=1
				`(?i)(UNION\s+(ALL\s+)?SELECT)`,                         // UNION SELECT
				`(?i)(SELECT\s+.+\s+FROM\s+)`,                          // SELECT ... FROM
				`(?i)(INSERT\s+INTO\s+)`,                                // INSERT INTO
				`(?i)(UPDATE\s+\w+\s+SET\s+)`,                          // UPDATE ... SET
				`(?i)(DELETE\s+FROM\s+)`,                                // DELETE FROM
				`(?i)(DROP\s+(TABLE|DATABASE|INDEX))`,                   // DROP TABLE/DATABASE
				`(?i)(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))`, // Stacked queries
			),
			Description: "SQL 구문 삽입을 통한 데이터베이스 조작 시도",
			Severity:    "HIGH",
		},
		{
			Name:     "SQLi-002",
			Category: "SQL Injection",
			Patterns: compilePatterns(
				`(?i)(';\s*--)`,          // '; --
				`(?i)('\s*--)`,           // ' --
				`(?i)(--\s*$)`,           // trailing --
				`(?i)(/\*.*\*/)`,         // /* comment */
				`(?i)(SLEEP\s*\()`,       // SLEEP() (time-based)
				`(?i)(BENCHMARK\s*\()`,   // BENCHMARK()
				`(?i)(WAITFOR\s+DELAY)`,  // WAITFOR DELAY (MSSQL)
			),
			Description: "SQL 주석 또는 시간 기반 블라인드 인젝션 시도",
			Severity:    "HIGH",
		},

		// XSS Rules
		{
			Name:     "XSS-001",
			Category: "XSS",
			Patterns: compilePatterns(
				`(?i)<\s*script[^>]*>`,                      // <script>
				`(?i)<\s*/\s*script\s*>`,                    // </script>
				`(?i)javascript\s*:`,                        // javascript:
				`(?i)on(error|load|click|mouseover|focus|blur|submit|change|input)\s*=`, // event handlers
				`(?i)<\s*img[^>]+on\w+\s*=`,                // <img onerror=
				`(?i)<\s*svg[^>]+on\w+\s*=`,                // <svg onload=
				`(?i)<\s*iframe`,                            // <iframe
				`(?i)<\s*embed`,                             // <embed
				`(?i)<\s*object`,                            // <object
			),
			Description: "악성 스크립트 삽입을 통한 사용자 브라우저 공격 시도",
			Severity:    "HIGH",
		},
		{
			Name:     "XSS-002",
			Category: "XSS",
			Patterns: compilePatterns(
				`(?i)document\s*\.\s*cookie`,      // document.cookie
				`(?i)document\s*\.\s*location`,    // document.location
				`(?i)window\s*\.\s*location`,      // window.location
				`(?i)alert\s*\(`,                  // alert(
				`(?i)eval\s*\(`,                   // eval(
				`(?i)fetch\s*\(`,                  // fetch(
				`(?i)XMLHttpRequest`,              // XMLHttpRequest
			),
			Description: "JavaScript를 이용한 정보 탈취 또는 리다이렉트 시도",
			Severity:    "MEDIUM",
		},

		// Path Traversal Rules
		{
			Name:     "PT-001",
			Category: "Path Traversal",
			Patterns: compilePatterns(
				`(\.\./|\.\.\\)`,                      // ../ or ..\
				`(?i)(/etc/(passwd|shadow|hosts))`,     // Linux sensitive files
				`(?i)(/(var|tmp|proc)/)`,               // Sensitive directories
				`(?i)(C:\\\\Windows)`,                  // Windows system
				`(?i)(boot\.ini|win\.ini)`,            // Windows config files
				`(?i)(%2e%2e%2f|%2e%2e/)`,             // URL encoded ../
				`(?i)(%252e%252e%252f)`,               // Double URL encoded
			),
			Description: "디렉토리 탐색을 통한 서버 내부 파일 접근 시도",
			Severity:    "HIGH",
		},

		// Command Injection Rules
		{
			Name:     "CMDi-001",
			Category: "Command Injection",
			Patterns: compilePatterns(
				`(;\s*(ls|cat|whoami|id|pwd|uname|wget|curl|rm|mv|cp|chmod|chown))`, // ; command
				`(\|\s*(ls|cat|whoami|id|pwd|uname|wget|curl|rm|mv|cp|chmod|chown))`, // | command
				`(\|\|)`,                             // ||
				`(&&\s*\w)`,                          // && command
				"(`[^`]+`)",                          // backtick execution
				`(\$\([^)]+\))`,                      // $(command)
				`(?i)(;\s*(net|ipconfig|systeminfo|tasklist|reg)\s)`, // Windows commands
			),
			Description: "서버에서 임의 명령어 실행을 시도",
			Severity:    "HIGH",
		},
	}
}

func compilePatterns(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			fmt.Printf("WARNING: Failed to compile pattern %q: %v\n", p, err)
			continue
		}
		compiled = append(compiled, r)
	}
	return compiled
}

// IsEnabled returns whether the WAF is currently enabled
func (w *WAFEngine) IsEnabled() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.enabled
}

// Toggle switches the WAF on/off and returns the new state
func (w *WAFEngine) Toggle() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = !w.enabled
	return w.enabled
}

// SetEnabled sets the WAF state directly
func (w *WAFEngine) SetEnabled(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = enabled
}

// Inspect checks the given input against all WAF rules
func (w *WAFEngine) Inspect(input string) WAFResult {
	w.mu.RLock()
	enabled := w.enabled
	w.mu.RUnlock()

	if !enabled {
		return WAFResult{Blocked: false}
	}

	// Normalize input for better detection
	normalized := normalizeInput(input)

	for _, rule := range w.rules {
		for _, pattern := range rule.Patterns {
			if loc := pattern.FindStringIndex(normalized); loc != nil {
				matched := normalized[loc[0]:loc[1]]
				return WAFResult{
					Blocked:     true,
					RuleName:    rule.Name,
					Category:    rule.Category,
					MatchedPart: matched,
					Description: rule.Description,
					Severity:    rule.Severity,
				}
			}
		}
	}

	return WAFResult{Blocked: false}
}

// AddLog records a WAF event
func (w *WAFEngine) AddLog(method, path, input, clientIP string, result WAFResult) {
	w.mu.Lock()
	defer w.mu.Unlock()

	logEntry := WAFLog{
		Timestamp: time.Now().Format("15:04:05"),
		Method:    method,
		Path:      path,
		Input:     truncate(input, 200),
		Result:    result,
		ClientIP:  clientIP,
	}

	w.logs = append(w.logs, logEntry)

	// Keep only last 100 logs
	if len(w.logs) > 100 {
		w.logs = w.logs[len(w.logs)-100:]
	}
}

// GetLogs returns all WAF logs
func (w *WAFEngine) GetLogs() []WAFLog {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]WAFLog, len(w.logs))
	copy(result, w.logs)
	return result
}

// ClearLogs clears all WAF logs
func (w *WAFEngine) ClearLogs() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = make([]WAFLog, 0)
}

// normalizeInput performs URL decoding and normalization
func normalizeInput(input string) string {
	s := input
	s = strings.ReplaceAll(s, "%27", "'")
	s = strings.ReplaceAll(s, "%22", "\"")
	s = strings.ReplaceAll(s, "%3C", "<")
	s = strings.ReplaceAll(s, "%3E", ">")
	s = strings.ReplaceAll(s, "%3c", "<")
	s = strings.ReplaceAll(s, "%3e", ">")
	s = strings.ReplaceAll(s, "%28", "(")
	s = strings.ReplaceAll(s, "%29", ")")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, "%2f", "/")
	s = strings.ReplaceAll(s, "%5C", "\\")
	s = strings.ReplaceAll(s, "%5c", "\\")
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
