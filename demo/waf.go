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

// ============================================================
// WAAP Engine - API Security, Bot Management, DDoS Protection
// ============================================================

// WAAPEngine integrates all WAAP modules
type WAAPEngine struct {
	APISecurity *APISecurityEngine
	BotMgmt     *BotManagementEngine
	DDoSProtect *DDoSProtectionEngine
	mu          sync.RWMutex
	logs        []WAFLog
}

// NewWAAPEngine creates and initializes the WAAP engine
func NewWAAPEngine() *WAAPEngine {
	return &WAAPEngine{
		APISecurity: NewAPISecurityEngine(),
		BotMgmt:     NewBotManagementEngine(),
		DDoSProtect: NewDDoSProtectionEngine(),
		logs:        make([]WAFLog, 0),
	}
}

// AddLog records a WAAP event
func (w *WAAPEngine) AddLog(method, path, input, clientIP string, result WAFResult) {
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
	if len(w.logs) > 100 {
		w.logs = w.logs[len(w.logs)-100:]
	}
}

// GetLogs returns all WAAP logs
func (w *WAAPEngine) GetLogs() []WAFLog {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]WAFLog, len(w.logs))
	copy(result, w.logs)
	return result
}

// ClearLogs clears all WAAP logs
func (w *WAAPEngine) ClearLogs() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = make([]WAFLog, 0)
}

// Reset resets all WAAP module states (counters, blocklists)
func (w *WAAPEngine) Reset() {
	w.APISecurity.Reset()
	w.BotMgmt.Reset()
	w.DDoSProtect.Reset()
}

// Status returns the enabled state of all modules
func (w *WAAPEngine) Status() map[string]bool {
	return map[string]bool{
		"apiSecurity": w.APISecurity.IsEnabled(),
		"botMgmt":     w.BotMgmt.IsEnabled(),
		"ddos":        w.DDoSProtect.IsEnabled(),
	}
}

// ============================================================
// API Security Engine - BOLA Detection + Rate Limiting
// ============================================================

type RequestCounter struct {
	Count     int
	FirstSeen time.Time
}

type APISecurityEngine struct {
	mu            sync.RWMutex
	enabled       bool
	requestCounts map[string]*RequestCounter
	rateLimit     int // max requests per window
	windowSec     int // window duration in seconds
}

type APISecurityResult struct {
	Blocked      bool   `json:"blocked"`
	Reason       string `json:"reason"`       // "BOLA", "RATE_LIMIT", ""
	Description  string `json:"description"`
	RequestCount int    `json:"requestCount"`
	RateLimit    int    `json:"rateLimit"`
}

func NewAPISecurityEngine() *APISecurityEngine {
	return &APISecurityEngine{
		enabled:       true,
		requestCounts: make(map[string]*RequestCounter),
		rateLimit:     10,
		windowSec:     60,
	}
}

func (a *APISecurityEngine) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *APISecurityEngine) Toggle() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = !a.enabled
	return a.enabled
}

func (a *APISecurityEngine) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requestCounts = make(map[string]*RequestCounter)
}

// CheckBOLA returns true if access should be blocked (user accessing another user's resource)
func (a *APISecurityEngine) CheckBOLA(tokenUserID, resourceOwnerID string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.enabled {
		return false
	}
	return tokenUserID != resourceOwnerID
}

// CheckRateLimit returns (blocked, currentCount)
func (a *APISecurityEngine) CheckRateLimit(clientKey string) (bool, int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return false, 0
	}

	now := time.Now()
	counter, exists := a.requestCounts[clientKey]

	if !exists || now.Sub(counter.FirstSeen) > time.Duration(a.windowSec)*time.Second {
		a.requestCounts[clientKey] = &RequestCounter{Count: 1, FirstSeen: now}
		return false, 1
	}

	counter.Count++
	if counter.Count > a.rateLimit {
		return true, counter.Count
	}
	return false, counter.Count
}

// ============================================================
// Bot Management Engine - Rate Detection + Behavior Analysis
// ============================================================

type BotTracker struct {
	Requests        []time.Time
	Blocked         bool
	ChallengeIssued bool
}

type BotManagementEngine struct {
	mu            sync.RWMutex
	enabled       bool
	requestLog    map[string]*BotTracker
	rateThreshold int // max requests per second before challenge
	blockThreshold int // max requests per second before block
}

type BotResult struct {
	Blocked         bool   `json:"blocked"`
	ChallengeIssued bool   `json:"challengeIssued"`
	Reason          string `json:"reason"` // "RATE_EXCEEDED", "NO_FINGERPRINT", "BLOCKED", ""
	Description     string `json:"description"`
	RequestsPerSec  float64 `json:"requestsPerSec"`
	BotScore        int    `json:"botScore"` // 0-100
}

func NewBotManagementEngine() *BotManagementEngine {
	return &BotManagementEngine{
		enabled:        true,
		requestLog:     make(map[string]*BotTracker),
		rateThreshold:  5,
		blockThreshold: 10,
	}
}

func (b *BotManagementEngine) IsEnabled() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.enabled
}

func (b *BotManagementEngine) Toggle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.enabled = !b.enabled
	return b.enabled
}

func (b *BotManagementEngine) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requestLog = make(map[string]*BotTracker)
}

// AnalyzeRequest checks if a request looks like a bot
func (b *BotManagementEngine) AnalyzeRequest(clientIP string, hasMouseEvents, hasBrowserFP bool) BotResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.enabled {
		return BotResult{Blocked: false, BotScore: 0}
	}

	now := time.Now()
	tracker, exists := b.requestLog[clientIP]

	if !exists {
		tracker = &BotTracker{Requests: make([]time.Time, 0)}
		b.requestLog[clientIP] = tracker
	}

	// If already blocked, stay blocked
	if tracker.Blocked {
		return BotResult{
			Blocked:     true,
			Reason:      "BLOCKED",
			Description: "이전 봇 탐지로 인해 차단된 IP입니다",
			BotScore:    100,
		}
	}

	// Record request
	tracker.Requests = append(tracker.Requests, now)

	// Keep only requests from last 3 seconds
	cutoff := now.Add(-3 * time.Second)
	filtered := make([]time.Time, 0)
	for _, t := range tracker.Requests {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	tracker.Requests = filtered

	// Calculate requests per second (over last 3 seconds)
	elapsed := now.Sub(filtered[0]).Seconds()
	if elapsed < 0.1 {
		elapsed = 0.1
	}
	rps := float64(len(filtered)) / elapsed

	// Calculate bot score
	botScore := 0
	if !hasMouseEvents {
		botScore += 30
	}
	if !hasBrowserFP {
		botScore += 30
	}
	if rps > float64(b.rateThreshold) {
		botScore += 40
	} else if rps > float64(b.rateThreshold)/2 {
		botScore += 20
	}
	if botScore > 100 {
		botScore = 100
	}

	// Block if rate exceeds block threshold
	if rps > float64(b.blockThreshold) {
		tracker.Blocked = true
		return BotResult{
			Blocked:        true,
			Reason:         "RATE_EXCEEDED",
			Description:    fmt.Sprintf("초당 %.1f회 요청 감지 - 자동화된 봇으로 판정하여 차단", rps),
			RequestsPerSec: rps,
			BotScore:       botScore,
		}
	}

	// Challenge if rate exceeds threshold or no fingerprint
	if rps > float64(b.rateThreshold) || (!hasMouseEvents && !hasBrowserFP) {
		tracker.ChallengeIssued = true
		reason := "RATE_EXCEEDED"
		desc := fmt.Sprintf("초당 %.1f회 요청 감지 - CAPTCHA 챌린지 발송", rps)
		if !hasMouseEvents && !hasBrowserFP {
			reason = "NO_FINGERPRINT"
			desc = "브라우저 핑거프린트/마우스 이벤트 없음 - 헤드리스 봇 의심"
		}
		return BotResult{
			Blocked:         true,
			ChallengeIssued: true,
			Reason:          reason,
			Description:     desc,
			RequestsPerSec:  rps,
			BotScore:        botScore,
		}
	}

	return BotResult{
		Blocked:        false,
		RequestsPerSec: rps,
		BotScore:       botScore,
	}
}

// ============================================================
// DDoS Protection Engine - HTTP Flood Detection
// ============================================================

type FloodTracker struct {
	Requests  []time.Time
	Blocked   bool
	BlockedAt time.Time
}

type DDoSProtectionEngine struct {
	mu              sync.RWMutex
	enabled         bool
	connectionCount map[string]*FloodTracker
	threshold       int // max requests per window
	windowSec       int // detection window in seconds
	blockDuration   int // block duration in seconds
}

type DDoSResult struct {
	Blocked        bool    `json:"blocked"`
	Reason         string  `json:"reason"` // "HTTP_FLOOD", "BLACKLISTED", ""
	Description    string  `json:"description"`
	RequestCount   int     `json:"requestCount"`
	Threshold      int     `json:"threshold"`
	RequestsPerSec float64 `json:"requestsPerSec"`
}

func NewDDoSProtectionEngine() *DDoSProtectionEngine {
	return &DDoSProtectionEngine{
		enabled:         true,
		connectionCount: make(map[string]*FloodTracker),
		threshold:       20,
		windowSec:       10,
		blockDuration:   30,
	}
}

func (d *DDoSProtectionEngine) IsEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

func (d *DDoSProtectionEngine) Toggle() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = !d.enabled
	return d.enabled
}

func (d *DDoSProtectionEngine) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connectionCount = make(map[string]*FloodTracker)
}

// CheckFlood analyzes request rate and returns whether to block
func (d *DDoSProtectionEngine) CheckFlood(clientIP string) DDoSResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return DDoSResult{Blocked: false}
	}

	now := time.Now()
	tracker, exists := d.connectionCount[clientIP]

	if !exists {
		tracker = &FloodTracker{Requests: make([]time.Time, 0)}
		d.connectionCount[clientIP] = tracker
	}

	// Check if currently blacklisted
	if tracker.Blocked {
		if now.Sub(tracker.BlockedAt) < time.Duration(d.blockDuration)*time.Second {
			return DDoSResult{
				Blocked:     true,
				Reason:      "BLACKLISTED",
				Description: fmt.Sprintf("HTTP Flood로 인한 블랙리스트 (%.0f초 남음)", float64(d.blockDuration)-now.Sub(tracker.BlockedAt).Seconds()),
				Threshold:   d.threshold,
			}
		}
		// Unblock after duration
		tracker.Blocked = false
		tracker.Requests = make([]time.Time, 0)
	}

	// Record request
	tracker.Requests = append(tracker.Requests, now)

	// Keep only requests within window
	cutoff := now.Add(-time.Duration(d.windowSec) * time.Second)
	filtered := make([]time.Time, 0)
	for _, t := range tracker.Requests {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	tracker.Requests = filtered

	// Calculate RPS
	rps := float64(0)
	if len(filtered) > 1 {
		elapsed := now.Sub(filtered[0]).Seconds()
		if elapsed < 0.1 {
			elapsed = 0.1
		}
		rps = float64(len(filtered)) / elapsed
	}

	// Check threshold
	if len(filtered) > d.threshold {
		tracker.Blocked = true
		tracker.BlockedAt = now
		return DDoSResult{
			Blocked:        true,
			Reason:         "HTTP_FLOOD",
			Description:    fmt.Sprintf("%d초간 %d회 요청 감지 (임계값: %d) - HTTP Flood 공격으로 판정", d.windowSec, len(filtered), d.threshold),
			RequestCount:   len(filtered),
			Threshold:      d.threshold,
			RequestsPerSec: rps,
		}
	}

	return DDoSResult{
		Blocked:        false,
		RequestCount:   len(filtered),
		Threshold:      d.threshold,
		RequestsPerSec: rps,
	}
}
