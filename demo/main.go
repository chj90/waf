package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

//go:embed index.html
var staticFiles embed.FS

var wafEngine *WAFEngine

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

	mux := http.NewServeMux()

	// Pages
	mux.HandleFunc("/", handleIndex)

	// Vulnerable endpoints
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/file", handleFile)
	mux.HandleFunc("/api/ping", handlePing)

	// WAF control
	mux.HandleFunc("/api/waf/toggle", handleWAFToggle)
	mux.HandleFunc("/api/waf/status", handleWAFStatus)
	mux.HandleFunc("/api/waf/logs", handleWAFLogs)
	mux.HandleFunc("/api/waf/logs/clear", handleWAFLogsClear)

	fmt.Println("==============================================")
	fmt.Println("  WAF Demo Server")
	fmt.Println("  http://localhost:8080")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("  WAF Status: ON")
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
