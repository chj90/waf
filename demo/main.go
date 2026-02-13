package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"sync"
)

//go:embed index.html
var staticFiles embed.FS

var wafEngine *WAFEngine
var waapEngine *WAAPEngine

// Simulated user database
var userDB = []map[string]string{
	{"id": "1", "username": "admin", "password": "admin123", "email": "admin@company.com", "role": "관리자", "phone": "010-1234-5678"},
	{"id": "2", "username": "user1", "password": "pass1234", "email": "user1@company.com", "role": "사용자", "phone": "010-2345-6789"},
	{"id": "3", "username": "user2", "password": "qwerty99", "email": "user2@company.com", "role": "사용자", "phone": "010-3456-7890"},
	{"id": "4", "username": "manager", "password": "mgr!@#$", "email": "mgr@company.com", "role": "매니저", "phone": "010-4567-8901"},
	{"id": "5", "username": "developer", "password": "dev2024!", "email": "dev@company.com", "role": "개발자", "phone": "010-5678-9012"},
}

// Simulated product database
var productDB = []map[string]string{
	{"id": "1", "name": "노트북 Pro 15", "price": "1,500,000원", "category": "전자제품"},
	{"id": "2", "name": "무선 마우스", "price": "35,000원", "category": "주변기기"},
	{"id": "3", "name": "기계식 키보드", "price": "89,000원", "category": "주변기기"},
	{"id": "4", "name": "27인치 모니터", "price": "450,000원", "category": "전자제품"},
	{"id": "5", "name": "USB-C 허브", "price": "55,000원", "category": "주변기기"},
}

// Simulated order database (for API Security demo)
var orderDB = []map[string]string{
	{"id": "5001", "userId": "user1", "product": "노트북 Pro 15", "amount": "1,500,000원", "status": "배송완료", "address": "서울시 강남구 테헤란로 123"},
	{"id": "5002", "userId": "user2", "product": "무선 마우스 외 3건", "amount": "285,000원", "status": "배송중", "address": "부산시 해운대구 센텀로 456"},
	{"id": "5003", "userId": "user3", "product": "기계식 키보드", "amount": "89,000원", "status": "결제완료", "address": "대전시 유성구 대학로 789"},
	{"id": "5004", "userId": "user4", "product": "27인치 모니터", "amount": "450,000원", "status": "배송완료", "address": "인천시 연수구 송도로 321"},
	{"id": "5005", "userId": "user5", "product": "USB-C 허브 외 1건", "amount": "110,000원", "status": "주문접수", "address": "광주시 서구 상무로 654"},
}

// Ticket state (for Bot Management demo)
var ticketMu sync.Mutex
var ticketRemaining = 487
var ticketTotal = 500
var ticketEvent = "2025 Super Concert"

// Simulated file system
var fakeFiles = map[string]string{
	"readme.txt":        "WAF 데모 애플리케이션입니다.\n버전: 1.0\n작성일: 2024-01-01",
	"notice.txt":        "서비스 점검 안내\n일시: 매주 화요일 02:00-04:00\n내용: 정기 보안 패치",
	"product_list.txt":  "상품 목록:\n1. 노트북 Pro 15\n2. 무선 마우스\n3. 기계식 키보드",
	"/etc/passwd":       "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\nwww-data:x:33:33:www-data:/var/www",
	"../../etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\nwww-data:x:33:33:www-data:/var/www",
	"../config/db.conf": "DB_HOST=192.168.1.100\nDB_PORT=3306\nDB_USER=root\nDB_PASS=super_secret_password!\nDB_NAME=production",
	"C:\\Windows\\win.ini": "[windows]\nload=\nrun=\nNullPort=None",
}

func main() {
	wafEngine = NewWAFEngine()
	waapEngine = NewWAAPEngine()

	mux := http.NewServeMux()

	// Pages
	mux.HandleFunc("/", handleIndex)

	// Vulnerable endpoints (WAF demo)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/file", handleFile)
	mux.HandleFunc("/api/ping", handlePing)

	// WAAP endpoints
	mux.HandleFunc("/api/orders", handleOrders)
	mux.HandleFunc("/api/tickets/purchase", handleTicketPurchase)
	mux.HandleFunc("/api/tickets/status", handleTicketStatus)
	mux.HandleFunc("/api/health", handleHealth)

	// WAF control
	mux.HandleFunc("/api/waf/toggle", handleWAFToggle)
	mux.HandleFunc("/api/waf/status", handleWAFStatus)
	mux.HandleFunc("/api/waf/logs", handleWAFLogs)
	mux.HandleFunc("/api/waf/logs/clear", handleWAFLogsClear)

	// WAAP control
	mux.HandleFunc("/api/waap/status", handleWAAPStatus)
	mux.HandleFunc("/api/waap/api-security/toggle", handleAPISecurityToggle)
	mux.HandleFunc("/api/waap/bot-mgmt/toggle", handleBotMgmtToggle)
	mux.HandleFunc("/api/waap/ddos/toggle", handleDDoSToggle)
	mux.HandleFunc("/api/waap/reset", handleWAAPReset)
	mux.HandleFunc("/api/waap/logs", handleWAAPLogs)
	mux.HandleFunc("/api/waap/logs/clear", handleWAAPLogsClear)

	fmt.Println("==============================================")
	fmt.Println("  WAAP Demo Server")
	fmt.Println("  http://localhost:8080")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("  WAF Status: ON")
	fmt.Println("  WAAP Modules: API Security / Bot Mgmt / DDoS")
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFiles.ReadFile("index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleLogin simulates a vulnerable login endpoint (SQL Injection target)
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	input := username + " " + password

	// Build the "SQL query" that would be executed
	simulatedQuery := fmt.Sprintf(
		"SELECT * FROM users WHERE username = '%s' AND password = '%s'",
		username, password,
	)

	// WAF Inspection
	result := wafEngine.Inspect(input)
	wafEngine.AddLog(r.Method, r.URL.Path, input, r.RemoteAddr, result)

	if result.Blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        false,
			"blocked":        true,
			"wafRule":        result.RuleName,
			"wafCategory":    result.Category,
			"wafDescription": result.Description,
			"wafSeverity":    result.Severity,
			"matchedPattern": result.MatchedPart,
			"simulatedQuery": simulatedQuery,
			"message":        fmt.Sprintf("[WAF] 차단됨 - %s 탐지 (Rule: %s)", result.Category, result.RuleName),
		})
		return
	}

	// Without WAF: simulate the SQL injection vulnerability
	isSQLInjection := strings.Contains(strings.ToLower(input), "' or") ||
		strings.Contains(strings.ToLower(input), "1=1") ||
		strings.Contains(strings.ToLower(input), "union select") ||
		strings.Contains(input, "' --") ||
		strings.Contains(input, "';")

	if isSQLInjection {
		// SQL Injection succeeded - return all users
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        true,
			"blocked":        false,
			"simulatedQuery": simulatedQuery,
			"message":        "SQL Injection 성공! 전체 사용자 정보가 유출되었습니다!",
			"data":           userDB,
			"alert":          "CRITICAL",
		})
		return
	}

	// Normal login check
	for _, user := range userDB {
		if user["username"] == username && user["password"] == password {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":        true,
				"blocked":        false,
				"simulatedQuery": simulatedQuery,
				"message":        fmt.Sprintf("로그인 성공! 환영합니다, %s님", username),
				"data":           []map[string]string{{"username": user["username"], "role": user["role"]}},
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        false,
		"blocked":        false,
		"simulatedQuery": simulatedQuery,
		"message":        "로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다",
	})
}

// handleSearch simulates a vulnerable search endpoint (XSS target)
func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		jsonError(w, "검색어를 입력해주세요", 400)
		return
	}

	// WAF Inspection
	result := wafEngine.Inspect(query)
	wafEngine.AddLog(r.Method, r.URL.Path, query, r.RemoteAddr, result)

	if result.Blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        false,
			"blocked":        true,
			"wafRule":        result.RuleName,
			"wafCategory":    result.Category,
			"wafDescription": result.Description,
			"wafSeverity":    result.Severity,
			"matchedPattern": result.MatchedPart,
			"searchQuery":    query,
			"message":        fmt.Sprintf("[WAF] 차단됨 - %s 탐지 (Rule: %s)", result.Category, result.RuleName),
		})
		return
	}

	// Check if input contains XSS
	hasXSS := strings.Contains(strings.ToLower(query), "<script") ||
		strings.Contains(strings.ToLower(query), "onerror") ||
		strings.Contains(strings.ToLower(query), "javascript:") ||
		strings.Contains(strings.ToLower(query), "onload")

	// Search products
	var results []map[string]string
	for _, p := range productDB {
		if strings.Contains(strings.ToLower(p["name"]), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(p["category"]), strings.ToLower(query)) {
			results = append(results, p)
		}
	}

	response := map[string]interface{}{
		"success":     true,
		"blocked":     false,
		"searchQuery": query,
		"resultCount": len(results),
		"data":        results,
	}

	if hasXSS {
		response["message"] = "XSS 공격 성공! 사용자 입력이 그대로 렌더링됩니다!"
		response["alert"] = "CRITICAL"
		response["renderedHTML"] = fmt.Sprintf(`<div class="search-result">검색어: %s<br>결과가 없습니다.</div>`, query)
		response["safeHTML"] = fmt.Sprintf(`<div class="search-result">검색어: %s<br>결과가 없습니다.</div>`, html.EscapeString(query))
	} else {
		response["message"] = fmt.Sprintf("'%s' 검색 결과: %d건", query, len(results))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleFile simulates a vulnerable file read endpoint (Path Traversal target)
func handleFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	if filename == "" {
		jsonError(w, "파일명을 입력해주세요", 400)
		return
	}

	// WAF Inspection
	result := wafEngine.Inspect(filename)
	wafEngine.AddLog(r.Method, r.URL.Path, filename, r.RemoteAddr, result)

	if result.Blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        false,
			"blocked":        true,
			"wafRule":        result.RuleName,
			"wafCategory":    result.Category,
			"wafDescription": result.Description,
			"wafSeverity":    result.Severity,
			"matchedPattern": result.MatchedPart,
			"requestedFile":  filename,
			"message":        fmt.Sprintf("[WAF] 차단됨 - %s 탐지 (Rule: %s)", result.Category, result.RuleName),
		})
		return
	}

	// Check if the file exists in our fake filesystem
	if content, ok := fakeFiles[filename]; ok {
		isTraversal := strings.Contains(filename, "..") ||
			strings.Contains(strings.ToLower(filename), "etc/passwd") ||
			strings.Contains(strings.ToLower(filename), "windows") ||
			strings.Contains(filename, "config")

		response := map[string]interface{}{
			"success":       true,
			"blocked":       false,
			"requestedFile": filename,
			"fileContent":   content,
		}

		if isTraversal {
			response["message"] = "Path Traversal 성공! 서버의 민감한 파일이 노출되었습니다!"
			response["alert"] = "CRITICAL"
		} else {
			response["message"] = fmt.Sprintf("파일 '%s' 읽기 성공", filename)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       false,
		"blocked":       false,
		"requestedFile": filename,
		"message":       fmt.Sprintf("파일 '%s'을(를) 찾을 수 없습니다", filename),
	})
}

// handlePing simulates a vulnerable ping endpoint (Command Injection target)
func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		jsonError(w, "호스트를 입력해주세요", 400)
		return
	}

	simulatedCommand := fmt.Sprintf("ping -c 4 %s", host)

	// WAF Inspection
	result := wafEngine.Inspect(host)
	wafEngine.AddLog(r.Method, r.URL.Path, host, r.RemoteAddr, result)

	if result.Blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          false,
			"blocked":          true,
			"wafRule":          result.RuleName,
			"wafCategory":     result.Category,
			"wafDescription":  result.Description,
			"wafSeverity":     result.Severity,
			"matchedPattern":  result.MatchedPart,
			"simulatedCommand": simulatedCommand,
			"message":         fmt.Sprintf("[WAF] 차단됨 - %s 탐지 (Rule: %s)", result.Category, result.RuleName),
		})
		return
	}

	// Check if it's a command injection attempt
	hasCmdInjection := strings.ContainsAny(host, ";|&`$") ||
		strings.Contains(host, "$(")

	if hasCmdInjection {
		// Simulate command injection results
		fakeOutput := fmt.Sprintf("PING %s: 56 data bytes\n", host)
		if strings.Contains(host, "whoami") {
			fakeOutput += "\nroot\n"
		} else if strings.Contains(host, "cat") && strings.Contains(host, "passwd") {
			fakeOutput += "\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
		} else if strings.Contains(host, "ls") {
			fakeOutput += "\napp.py\nconfig.py\ndatabase.db\nrequirements.txt\n.env\n"
		} else if strings.Contains(host, "id") {
			fakeOutput += "\nuid=0(root) gid=0(root) groups=0(root)\n"
		} else {
			fakeOutput += "\n[Command executed successfully]\n"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          true,
			"blocked":          false,
			"simulatedCommand": simulatedCommand,
			"output":           fakeOutput,
			"message":          "Command Injection 성공! 서버에서 임의 명령이 실행되었습니다!",
			"alert":            "CRITICAL",
		})
		return
	}

	// Normal ping response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"blocked":          false,
		"simulatedCommand": simulatedCommand,
		"output": fmt.Sprintf(
			"PING %s: 56 data bytes\n64 bytes from %s: icmp_seq=1 ttl=64 time=1.23 ms\n64 bytes from %s: icmp_seq=2 ttl=64 time=0.98 ms\n--- %s ping statistics ---\n2 packets transmitted, 2 received, 0%% packet loss",
			host, host, host, host,
		),
		"message": fmt.Sprintf("ping %s 완료", host),
	})
}

// WAF Control Handlers

func handleWAFToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}

	newState := wafEngine.Toggle()
	status := "OFF"
	if newState {
		status = "ON"
	}

	fmt.Printf("  WAF Status changed: %s\n", status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": newState,
		"message": fmt.Sprintf("WAF가 %s 되었습니다", status),
	})
}

func handleWAFStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": wafEngine.IsEnabled(),
	})
}

func handleWAFLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wafEngine.GetLogs())
}

func handleWAFLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	wafEngine.ClearLogs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "로그가 삭제되었습니다",
	})
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": message,
	})
}

// ============================================================
// WAAP Handlers - API Security
// ============================================================

func handleOrders(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("id")
	if orderID == "" {
		jsonError(w, "주문번호를 입력해주세요", 400)
		return
	}

	// Simulated authentication: X-User-Token header
	tokenUser := r.Header.Get("X-User-Token")
	if tokenUser == "" {
		tokenUser = "user1" // default
	}

	// Rate limit check first
	rateLimited, reqCount := waapEngine.APISecurity.CheckRateLimit(tokenUser)
	if rateLimited {
		result := WAFResult{
			Blocked:     true,
			RuleName:    "API-RATE",
			Category:    "API Rate Limit",
			MatchedPart: fmt.Sprintf("%d requests", reqCount),
			Description: fmt.Sprintf("API 호출 횟수 초과 (%d/%d) - 비정상적인 대량 조회 차단", reqCount, waapEngine.APISecurity.rateLimit),
			Severity:    "MEDIUM",
		}
		waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("order=%s token=%s", orderID, tokenUser), r.RemoteAddr, result)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"blocked":      true,
			"reason":       "RATE_LIMIT",
			"message":      fmt.Sprintf("[WAAP] API Rate Limit 초과 - %d/%d회 요청 차단", reqCount, waapEngine.APISecurity.rateLimit),
			"requestCount": reqCount,
			"rateLimit":    waapEngine.APISecurity.rateLimit,
			"category":     "API Rate Limit",
		})
		return
	}

	// Find the order
	var order map[string]string
	for _, o := range orderDB {
		if o["id"] == orderID {
			order = o
			break
		}
	}

	if order == nil {
		result := WAFResult{Blocked: false}
		waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("order=%s token=%s", orderID, tokenUser), r.RemoteAddr, result)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  false,
			"blocked":  false,
			"message":  fmt.Sprintf("주문번호 '%s'을(를) 찾을 수 없습니다", orderID),
			"category": "API Security",
		})
		return
	}

	// BOLA check
	isBOLA := waapEngine.APISecurity.CheckBOLA(tokenUser, order["userId"])
	if isBOLA {
		result := WAFResult{
			Blocked:     true,
			RuleName:    "API-BOLA",
			Category:    "API Security (BOLA)",
			MatchedPart: fmt.Sprintf("token=%s, owner=%s", tokenUser, order["userId"]),
			Description: fmt.Sprintf("인증 토큰(%s)과 리소스 소유자(%s) 불일치 - 타인의 주문 정보 접근 차단", tokenUser, order["userId"]),
			Severity:    "HIGH",
		}
		waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("order=%s token=%s", orderID, tokenUser), r.RemoteAddr, result)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        false,
			"blocked":        true,
			"reason":         "BOLA",
			"message":        fmt.Sprintf("[WAAP] BOLA 탐지 - 사용자 '%s'이(가) '%s' 소유의 주문에 접근 시도", tokenUser, order["userId"]),
			"tokenUser":      tokenUser,
			"resourceOwner":  order["userId"],
			"category":       "API Security (BOLA)",
			"description":    "인증 토큰의 사용자 ID와 주문 소유자 불일치 탐지",
			"requestCount":   reqCount,
		})
		return
	}

	// Access allowed
	result := WAFResult{Blocked: false}
	waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("order=%s token=%s", orderID, tokenUser), r.RemoteAddr, result)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"blocked":      false,
		"message":      fmt.Sprintf("주문 #%s 조회 성공", orderID),
		"data":         order,
		"tokenUser":    tokenUser,
		"requestCount": reqCount,
		"category":     "API Security",
	})
}

// ============================================================
// WAAP Handlers - Bot Management
// ============================================================

func handleTicketPurchase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}

	hasMouseEvents := r.Header.Get("X-Mouse-Events") == "true"
	hasBrowserFP := r.Header.Get("X-Browser-FP") == "true"

	botResult := waapEngine.BotMgmt.AnalyzeRequest(r.RemoteAddr, hasMouseEvents, hasBrowserFP)

	if botResult.Blocked {
		result := WAFResult{
			Blocked:     true,
			RuleName:    "BOT-" + botResult.Reason,
			Category:    "Bot Management",
			MatchedPart: fmt.Sprintf("score=%d, rps=%.1f", botResult.BotScore, botResult.RequestsPerSec),
			Description: botResult.Description,
			Severity:    "HIGH",
		}
		waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("mouse=%v fp=%v", hasMouseEvents, hasBrowserFP), r.RemoteAddr, result)

		status := 403
		if botResult.ChallengeIssued {
			status = 423 // Locked - CAPTCHA required
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         false,
			"blocked":         true,
			"challengeIssued": botResult.ChallengeIssued,
			"reason":          botResult.Reason,
			"message":         fmt.Sprintf("[WAAP] Bot 탐지 - %s", botResult.Description),
			"botScore":        botResult.BotScore,
			"requestsPerSec":  botResult.RequestsPerSec,
			"category":        "Bot Management",
		})
		return
	}

	// Purchase successful
	ticketMu.Lock()
	purchased := false
	if ticketRemaining > 0 {
		ticketRemaining--
		purchased = true
	}
	remaining := ticketRemaining
	ticketMu.Unlock()

	result := WAFResult{Blocked: false}
	waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("mouse=%v fp=%v", hasMouseEvents, hasBrowserFP), r.RemoteAddr, result)

	if purchased {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        true,
			"blocked":        false,
			"message":        fmt.Sprintf("티켓 구매 성공! (%s)", ticketEvent),
			"remaining":      remaining,
			"total":          ticketTotal,
			"botScore":       botResult.BotScore,
			"requestsPerSec": botResult.RequestsPerSec,
			"category":       "Bot Management",
		})
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   false,
			"blocked":   false,
			"message":   "매진되었습니다",
			"remaining": 0,
			"total":     ticketTotal,
			"category":  "Bot Management",
		})
	}
}

func handleTicketStatus(w http.ResponseWriter, r *http.Request) {
	ticketMu.Lock()
	remaining := ticketRemaining
	ticketMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"event":     ticketEvent,
		"total":     ticketTotal,
		"remaining": remaining,
	})
}

// ============================================================
// WAAP Handlers - DDoS Protection
// ============================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	ddosResult := waapEngine.DDoSProtect.CheckFlood(r.RemoteAddr)

	if ddosResult.Blocked {
		result := WAFResult{
			Blocked:     true,
			RuleName:    "DDOS-" + ddosResult.Reason,
			Category:    "DDoS Protection",
			MatchedPart: fmt.Sprintf("reqs=%d, rps=%.1f", ddosResult.RequestCount, ddosResult.RequestsPerSec),
			Description: ddosResult.Description,
			Severity:    "HIGH",
		}
		waapEngine.AddLog(r.Method, r.URL.Path, fmt.Sprintf("requests=%d", ddosResult.RequestCount), r.RemoteAddr, result)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        false,
			"blocked":        true,
			"reason":         ddosResult.Reason,
			"message":        fmt.Sprintf("[WAAP] DDoS 차단 - %s", ddosResult.Description),
			"requestCount":   ddosResult.RequestCount,
			"threshold":      ddosResult.Threshold,
			"requestsPerSec": ddosResult.RequestsPerSec,
			"category":       "DDoS Protection",
		})
		return
	}

	result := WAFResult{Blocked: false}
	waapEngine.AddLog(r.Method, r.URL.Path, "health check", r.RemoteAddr, result)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"blocked":        false,
		"message":        "Service OK",
		"status":         "healthy",
		"requestCount":   ddosResult.RequestCount,
		"threshold":      ddosResult.Threshold,
		"requestsPerSec": ddosResult.RequestsPerSec,
		"category":       "DDoS Protection",
	})
}

// ============================================================
// WAAP Control Handlers
// ============================================================

func handleWAAPStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(waapEngine.Status())
}

func handleAPISecurityToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	newState := waapEngine.APISecurity.Toggle()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": newState,
		"module":  "API Security",
	})
}

func handleBotMgmtToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	newState := waapEngine.BotMgmt.Toggle()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": newState,
		"module":  "Bot Management",
	})
}

func handleDDoSToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	newState := waapEngine.DDoSProtect.Toggle()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": newState,
		"module":  "DDoS Protection",
	})
}

func handleWAAPReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	waapEngine.Reset()
	// Reset ticket count too
	ticketMu.Lock()
	ticketRemaining = 487
	ticketMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "WAAP 상태가 초기화되었습니다",
	})
}

func handleWAAPLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(waapEngine.GetLogs())
}

func handleWAAPLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", 405)
		return
	}
	waapEngine.ClearLogs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "WAAP 로그가 삭제되었습니다",
	})
}
