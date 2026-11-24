package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTestLibsql(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("libsql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func writeHranaJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestHranaOpenDSN(t *testing.T) {
	d := &hranaDriver{}
	cases := []struct {
		name         string
		dsn          string
		wantEndpoint string
		wantToken    string
		wantErr      bool
	}{
		{
			name:         "libsql default https",
			dsn:          "libsql://db.turso.io?authToken=tok123",
			wantEndpoint: "https://db.turso.io/v2/pipeline",
			wantToken:    "tok123",
		},
		{
			name:         "libsql tls=false",
			dsn:          "libsql://localhost:8080?tls=false&authToken=tok",
			wantEndpoint: "http://localhost:8080/v2/pipeline",
			wantToken:    "tok",
		},
		{
			name:         "libsql tls=0",
			dsn:          "libsql://localhost:8080?tls=0",
			wantEndpoint: "http://localhost:8080/v2/pipeline",
		},
		{
			name:         "preserves path and extra query params without fragment",
			dsn:          "libsql://db.turso.io/prefix/?foo=bar&authToken=secret#frag",
			wantEndpoint: "https://db.turso.io/prefix/v2/pipeline?foo=bar",
			wantToken:    "secret",
		},
		{
			name:         "ws and wss",
			dsn:          "ws://127.0.0.1:8080/",
			wantEndpoint: "http://127.0.0.1:8080/v2/pipeline",
		},
		{
			name:         "wss ignores tls=false",
			dsn:          "wss://db.turso.io?tls=false",
			wantEndpoint: "https://db.turso.io/v2/pipeline",
		},
		{
			name:         "http and https",
			dsn:          "http://127.0.0.1:8080",
			wantEndpoint: "http://127.0.0.1:8080/v2/pipeline",
		},
		{
			name:    "unsupported scheme",
			dsn:     "file:///tmp/test.db",
			wantErr: true,
		},
		{
			name:    "missing host",
			dsn:     "libsql://?authToken=tok",
			wantErr: true,
		},
		{
			name:    "invalid url does not leak token",
			dsn:     "libsql://bad\x7fhost?authToken=SUPERSECRET",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := d.Open(tc.dsn)
			if tc.wantErr {
				if err == nil {
					c.Close()
					t.Fatalf("expected error for %q, got nil", tc.dsn)
				}
				if strings.Contains(err.Error(), "SUPERSECRET") {
					t.Fatalf("error leaked authToken: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open(%q): %v", tc.dsn, err)
			}
			defer c.Close()
			hc := c.(*hranaConn)
			if hc.endpoint != tc.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", hc.endpoint, tc.wantEndpoint)
			}
			if hc.token != tc.wantToken {
				t.Errorf("token = %q, want %q", hc.token, tc.wantToken)
			}
		})
	}
}

func TestHranaPingAndAuth(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var gotReq hranaPipelineReq

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode req: %v", err)
		}
		writeHranaJSON(t, w, map[string]any{
			"baton": nil,
			"results": []any{
				map[string]any{"type": "ok", "response": map[string]any{"type": "execute", "result": map[string]any{"cols": []any{}, "rows": []any{}}}},
				map[string]any{"type": "ok", "response": map[string]any{"type": "close"}},
			},
		})
	}))
	defer srv.Close()

	db := openTestLibsql(t, srv.URL+"?authToken=my-secret-jwt")
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext: %v", err)
	}
	if gotPath != "/v2/pipeline" {
		t.Errorf("path = %q, want /v2/pipeline", gotPath)
	}
	if gotAuth != "Bearer my-secret-jwt" {
		t.Errorf("Authorization = %q, want Bearer my-secret-jwt", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if len(gotReq.Requests) != 2 || gotReq.Requests[0].Type != "execute" || gotReq.Requests[0].Stmt.SQL != "SELECT 1" || gotReq.Requests[1].Type != "close" {
		t.Errorf("unexpected ping pipeline requests: %+v", gotReq.Requests)
	}

	// Without token: Authorization header must be absent.
	gotAuth = "sentinel"
	dbNoAuth := openTestLibsql(t, srv.URL)
	if err := dbNoAuth.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext without token: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected empty Authorization header without token, got %q", gotAuth)
	}
}

func TestHranaExecContext(t *testing.T) {
	cases := []struct {
		name         string
		rawRowID     any
		affected     int64
		wantLastID   int64
		wantAffected int64
	}{
		{"string rowid", "9007199254740993", 3, 9007199254740993, 3},
		{"numeric rowid", 42, 1, 42, 1},
		{"null rowid", nil, 5, 0, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeHranaJSON(t, w, map[string]any{
					"baton": nil,
					"results": []any{
						map[string]any{
							"type": "ok",
							"response": map[string]any{
								"type": "execute",
								"result": map[string]any{
									"cols":               []any{},
									"rows":               []any{},
									"affected_row_count": tc.affected,
									"last_insert_rowid":  tc.rawRowID,
								},
							},
						},
						map[string]any{"type": "ok", "response": map[string]any{"type": "close"}},
					},
				})
			}))
			defer srv.Close()

			db := openTestLibsql(t, srv.URL)
			res, err := db.ExecContext(context.Background(), "INSERT INTO t VALUES (?)", "x")
			if err != nil {
				t.Fatalf("ExecContext: %v", err)
			}
			gotID, err := res.LastInsertId()
			if err != nil || gotID != tc.wantLastID {
				t.Errorf("LastInsertId() = %d, %v; want %d", gotID, err, tc.wantLastID)
			}
			gotAff, err := res.RowsAffected()
			if err != nil || gotAff != tc.wantAffected {
				t.Errorf("RowsAffected() = %d, %v; want %d", gotAff, err, tc.wantAffected)
			}
		})
	}
}

func TestHranaQueryContextAndDecode(t *testing.T) {
	rawBlob := []byte{0xde, 0xad, 0xbe, 0xef, 0x01} // len 5 -> requires '=' padding in StdEncoding
	unpadded := base64.RawStdEncoding.EncodeToString(rawBlob)
	padded := base64.StdEncoding.EncodeToString(rawBlob)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeHranaJSON(t, w, map[string]any{
			"baton": nil,
			"results": []any{
				map[string]any{
					"type": "ok",
					"response": map[string]any{
						"type": "execute",
						"result": map[string]any{
							"cols": []map[string]string{
								{"name": "i_str"},
								{"name": "i_num"},
								{"name": "f"},
								{"name": "s"},
								{"name": "b_pad"},
								{"name": "b_nopad"},
								{"name": "n"},
							},
							"rows": [][]map[string]any{
								{
									{"type": "integer", "value": "1234567890123"},
									{"type": "integer", "value": -7},
									{"type": "float", "value": 3.5},
									{"type": "text", "value": "hello"},
									{"type": "blob", "base64": padded},
									{"type": "blob", "base64": unpadded},
									{"type": "null"},
								},
								{
									{"type": "integer", "value": "0"},
									{"type": "integer", "value": 0},
									{"type": "float", "value": 0},
									{"type": "text", "value": ""},
									{"type": "blob", "base64": ""},
									{"type": "blob", "base64": ""},
									{"type": "null"},
								},
							},
						},
					},
				},
				map[string]any{"type": "ok", "response": map[string]any{"type": "close"}},
			},
		})
	}))
	defer srv.Close()

	db := openTestLibsql(t, srv.URL)
	rows, err := db.QueryContext(context.Background(), "SELECT * FROM demo")
	if err != nil {
		t.Fatalf("QueryContext: %v", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil || len(cols) != 7 || cols[0] != "i_str" || cols[6] != "n" {
		t.Fatalf("Columns() = %v, %v", cols, err)
	}

	// Row 1
	if !rows.Next() {
		t.Fatalf("expected row 1, err=%v", rows.Err())
	}
	var iStr, iNum int64
	var f float64
	var s string
	var bPad, bNoPad []byte
	var nullStr sql.NullString
	if err := rows.Scan(&iStr, &iNum, &f, &s, &bPad, &bNoPad, &nullStr); err != nil {
		t.Fatalf("Scan row 1: %v", err)
	}
	if iStr != 1234567890123 || iNum != -7 || f != 3.5 || s != "hello" || !bytes.Equal(bPad, rawBlob) || !bytes.Equal(bNoPad, rawBlob) || nullStr.Valid {
		t.Errorf("row 1 mismatch: iStr=%d iNum=%d f=%v s=%q bPad=%x bNoPad=%x null=%+v", iStr, iNum, f, s, bPad, bNoPad, nullStr)
	}

	// Row 2 (zero values)
	if !rows.Next() {
		t.Fatalf("expected row 2, err=%v", rows.Err())
	}
	if err := rows.Scan(&iStr, &iNum, &f, &s, &bPad, &bNoPad, &nullStr); err != nil {
		t.Fatalf("Scan row 2: %v", err)
	}
	if iStr != 0 || iNum != 0 || f != 0 || s != "" || len(bPad) != 0 || len(bNoPad) != 0 || nullStr.Valid {
		t.Errorf("row 2 mismatch: iStr=%d iNum=%d f=%v s=%q bPad=%x bNoPad=%x null=%+v", iStr, iNum, f, s, bPad, bNoPad, nullStr)
	}

	if rows.Next() {
		t.Fatal("expected EOF after 2 rows")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
}

func TestHranaArgEncodingWireJSON(t *testing.T) {
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		rawBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		writeHranaJSON(t, w, map[string]any{
			"baton": nil,
			"results": []any{
				map[string]any{"type": "ok", "response": map[string]any{"type": "execute", "result": map[string]any{"cols": []any{}, "rows": []any{}}}},
				map[string]any{"type": "ok", "response": map[string]any{"type": "close"}},
			},
		})
	}))
	defer srv.Close()

	db := openTestLibsql(t, srv.URL)
	ts := time.Date(2026, 11, 24, 14, 30, 0, 123000000, time.UTC)
	var nilBlob []byte
	emptyBlob := []byte{}

	_, err := db.ExecContext(
		context.Background(),
		"INSERT INTO t VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
		nil,
		int64(0),
		int64(-99),
		float64(0),
		float64(1.25),
		true,
		false,
		"",
		"abc",
		emptyBlob,
		[]byte("hi"),
		nilBlob,
		ts,
		sql.Named("tag", ""),
	)
	if err != nil {
		t.Fatalf("ExecContext: %v", err)
	}

	var parsed struct {
		Requests []struct {
			Type string `json:"type"`
			Stmt *struct {
				SQL       string            `json:"sql"`
				Args      []json.RawMessage `json:"args"`
				NamedArgs []struct {
					Name  string          `json:"name"`
					Value json.RawMessage `json:"value"`
				} `json:"named_args"`
			} `json:"stmt"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		t.Fatalf("unmarshal wire body: %v\nbody=%s", err, rawBody)
	}
	wantArgs := []string{
		`{"type":"null"}`,
		`{"type":"integer","value":"0"}`,
		`{"type":"integer","value":"-99"}`,
		`{"type":"float","value":0}`,
		`{"type":"float","value":1.25}`,
		`{"type":"integer","value":"1"}`,
		`{"type":"integer","value":"0"}`,
		`{"type":"text","value":""}`,
		`{"type":"text","value":"abc"}`,
		`{"type":"blob","base64":""}`,
		`{"type":"blob","base64":"aGk="}`,
		`{"type":"null"}`,
		`{"type":"text","value":"2026-11-24T14:30:00.123Z"}`,
	}
	gotArgs := parsed.Requests[0].Stmt.Args
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("len(args) = %d, want %d\nbody=%s", len(gotArgs), len(wantArgs), rawBody)
	}
	for i, want := range wantArgs {
		if string(gotArgs[i]) != want {
			t.Errorf("arg[%d] = %s, want %s", i, gotArgs[i], want)
		}
	}
	named := parsed.Requests[0].Stmt.NamedArgs
	if len(named) != 1 || named[0].Name != "tag" || string(named[0].Value) != `{"type":"text","value":""}` {
		t.Errorf("named_args = %+v, want [{tag {\"type\":\"text\",\"value\":\"\"}}]", named)
	}
}

func TestHranaEncodeArgsErrors(t *testing.T) {
	for _, v := range []any{math.NaN(), math.Inf(1), math.Inf(-1), struct{}{}} {
		if _, _, err := encodeArgs([]driver.NamedValue{{Ordinal: 1, Value: v}}); err == nil {
			t.Errorf("encodeArgs(%v) expected error, got nil", v)
		}
	}
}

func TestHranaDecodeValueErrors(t *testing.T) {
	bad := []hranaRawValue{
		{Type: "bogus"},
		{Type: "integer", Value: json.RawMessage(`"not-an-int"`)},
		{Type: "integer", Value: json.RawMessage(`null`)},
		{Type: "float", Value: json.RawMessage(`null`)},
		{Type: "float", Value: json.RawMessage(`"nope"`)},
		{Type: "text", Value: json.RawMessage(`null`)},
		{Type: "text", Value: json.RawMessage(`123`)},
		{Type: "blob", Base64: "!!!not-base64!!!"},
	}
	for _, rv := range bad {
		if v, err := decodeValue(rv); err == nil {
			t.Errorf("decodeValue(%+v) = %v, want error", rv, v)
		}
	}
}

func TestHranaTransactionsCommitRollbackAndBaseURL(t *testing.T) {
	type call struct {
		server string
		baton  string
		reqs   []string
	}
	var mu sync.Mutex
	var calls []call

	record := func(srvName string, r *http.Request) hranaPipelineReq {
		var req hranaPipelineReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode req: %v", err)
		}
		var types []string
		for _, rr := range req.Requests {
			if rr.Stmt != nil {
				types = append(types, rr.Type+":"+rr.Stmt.SQL)
			} else {
				types = append(types, rr.Type)
			}
		}
		mu.Lock()
		calls = append(calls, call{server: srvName, baton: req.Baton, reqs: types})
		mu.Unlock()
		return req
	}

	okResults := func(req hranaPipelineReq) []any {
		out := make([]any, 0, len(req.Requests))
		for _, rr := range req.Requests {
			if rr.Type == "close" {
				out = append(out, map[string]any{"type": "ok", "response": map[string]any{"type": "close"}})
			} else {
				out = append(out, map[string]any{
					"type": "ok",
					"response": map[string]any{
						"type": "execute",
						"result": map[string]any{
							"cols":               []map[string]string{{"name": "v"}},
							"rows":               [][]map[string]any{{{"type": "integer", "value": "7"}}},
							"affected_row_count": 1,
							"last_insert_rowid":  "1",
						},
					},
				})
			}
		}
		return out
	}

	// Replica server handles sticky base_url requests during the transaction.
	replica := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := record("replica", r)
		nextBaton := "b2"
		for _, rr := range req.Requests {
			if rr.Type == "close" {
				nextBaton = ""
			}
		}
		writeHranaJSON(t, w, map[string]any{
			"baton":   nextBaton,
			"results": okResults(req),
		})
	}))
	defer replica.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := record("primary", r)
		nextBaton := "b1"
		baseURL := replica.URL
		for _, rr := range req.Requests {
			if rr.Type == "close" {
				nextBaton = ""
				baseURL = ""
			}
		}
		writeHranaJSON(t, w, map[string]any{
			"baton":    nextBaton,
			"base_url": baseURL,
			"results":  okResults(req),
		})
	}))
	defer primary.Close()

	db := openTestLibsql(t, primary.URL)
	db.SetMaxOpenConns(1)

	// 1. Commit flow with sticky base_url
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO t VALUES (1)"); err != nil {
		t.Fatalf("tx.ExecContext: %v", err)
	}
	var v int
	if err := tx.QueryRowContext(context.Background(), "SELECT 7").Scan(&v); err != nil || v != 7 {
		t.Fatalf("tx.QueryRowContext: v=%d err=%v", v, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// 2. Standalone query after commit must go back to primary with empty baton.
	if err := db.QueryRowContext(context.Background(), "SELECT 7").Scan(&v); err != nil || v != 7 {
		t.Fatalf("post-commit query: v=%d err=%v", v, err)
	}

	// 3. Rollback flow with a CANCELED tx context: ROLLBACK + close must still reach server!
	txCtx, cancel := context.WithCancel(context.Background())
	tx2, err := db.BeginTx(txCtx, nil)
	if err != nil {
		t.Fatalf("BeginTx 2: %v", err)
	}
	cancel()
	// Wait briefly or call Rollback directly; database/sql may also trigger rollback via awaitDone.
	_ = tx2.Rollback()

	// Verify exact call sequence.
	mu.Lock()
	got := append([]call(nil), calls...)
	mu.Unlock()

	if len(got) < 7 {
		t.Fatalf("expected at least 7 calls, got %d: %+v", len(got), got)
	}
	if got[0].server != "primary" || got[0].baton != "" || strings.Join(got[0].reqs, ",") != "execute:BEGIN IMMEDIATE" {
		t.Errorf("call[0] = %+v", got[0])
	}
	if got[1].server != "replica" || got[1].baton != "b1" || strings.Join(got[1].reqs, ",") != "execute:INSERT INTO t VALUES (1)" {
		t.Errorf("call[1] = %+v", got[1])
	}
	if got[2].server != "replica" || got[2].baton != "b2" || strings.Join(got[2].reqs, ",") != "execute:SELECT 7" {
		t.Errorf("call[2] = %+v", got[2])
	}
	if got[3].server != "replica" || got[3].baton != "b2" || strings.Join(got[3].reqs, ",") != "execute:COMMIT,close" {
		t.Errorf("call[3] = %+v", got[3])
	}
	if got[4].server != "primary" || got[4].baton != "" || strings.Join(got[4].reqs, ",") != "execute:SELECT 7,close" {
		t.Errorf("call[4] = %+v", got[4])
	}
	if got[5].server != "primary" || got[5].baton != "" || strings.Join(got[5].reqs, ",") != "execute:BEGIN IMMEDIATE" {
		t.Errorf("call[5] = %+v", got[5])
	}
	if got[6].server != "replica" || got[6].baton != "b1" || strings.Join(got[6].reqs, ",") != "execute:ROLLBACK,close" {
		t.Errorf("call[6] = %+v", got[6])
	}

	// 4. Read-only transaction uses plain BEGIN (not BEGIN IMMEDIATE).
	txRO, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("BeginTx read-only: %v", err)
	}
	if err := txRO.Rollback(); err != nil {
		t.Fatalf("Rollback read-only: %v", err)
	}
	mu.Lock()
	roCall := calls[len(calls)-2]
	mu.Unlock()
	if strings.Join(roCall.reqs, ",") != "execute:BEGIN" {
		t.Errorf("read-only begin call = %+v, want execute:BEGIN", roCall)
	}

	// 5. Unsupported isolation level returns error.
	if _, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable}); err == nil {
		t.Error("expected error for unsupported isolation level")
	}
}

func TestHranaBaseURLDowngradeRejected(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		raw      string
		want     string
		wantErr  bool
	}{
		{"https downgrade rejected", "https://db.turso.io/v2/pipeline", "http://db.turso.io", "", true},
		{"unsupported scheme rejected", "https://db.turso.io/v2/pipeline", "file:///etc/passwd", "", true},
		{"userinfo rejected", "https://db.turso.io/v2/pipeline", "https://user:pass@replica.turso.io", "", true},
		{"username-only rejected", "https://db.turso.io/v2/pipeline", "https://user@db.turso.io", "", true},
		{"cross-domain rejected", "https://db.turso.io/v2/pipeline", "https://attacker.example.com", "", true},
		{"suffix-spoof rejected", "https://db.turso.io/v2/pipeline", "https://turso.io.evil.com", "", true},
		{"lookalike domain rejected", "https://db.turso.io/v2/pipeline", "https://not-turso.io", "", true},
		{"ip target from domain rejected", "https://db.turso.io/v2/pipeline", "https://169.254.169.254", "", true},
		{"different ip rejected", "http://127.0.0.1:8080/v2/pipeline", "http://169.254.169.254", "", true},
		{"ccTLD cross-tenant rejected", "https://app.example.co.uk/v2/pipeline", "https://evil.co.uk", "", true},
		{"same ip different port allowed", "http://127.0.0.1:8080/v2/pipeline", "http://127.0.0.1:9090", "http://127.0.0.1:9090/v2/pipeline", false},
		{"same host allowed", "https://db.turso.io/v2/pipeline", "https://db.turso.io", "https://db.turso.io/v2/pipeline", false},
		{"sibling subdomain allowed", "https://db.turso.io/v2/pipeline", "https://replica.turso.io", "https://replica.turso.io/v2/pipeline", false},
		{"multi-level turso subdomain allowed", "https://db.aws-us-east-1.turso.io/v2/pipeline", "https://replica.aws-eu-west-1.turso.io", "https://replica.aws-eu-west-1.turso.io/v2/pipeline", false},
		{"ccTLD sibling subdomain allowed", "https://app.example.co.uk/v2/pipeline", "https://replica.example.co.uk", "https://replica.example.co.uk/v2/pipeline", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &hranaConn{baseEndpoint: tc.base, endpoint: tc.base}
			err := c.applyBaseURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("applyBaseURL(%q) = nil, want error", tc.raw)
				}
				if c.endpoint != tc.base {
					t.Errorf("endpoint mutated on error: got %q, want %q", c.endpoint, tc.base)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyBaseURL(%q) unexpected error: %v", tc.raw, err)
			}
			if c.endpoint != tc.want {
				t.Errorf("endpoint = %q, want %q", c.endpoint, tc.want)
			}
		})
	}
}

func TestHranaErrorResponses(t *testing.T) {
	t.Run("http 401 and truncation", func(t *testing.T) {
		longBody := strings.Repeat("E", 1000)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(longBody))
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL)
		err := db.PingContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "libsql http 401") {
			t.Fatalf("expected http 401 error, got %v", err)
		}
		if len(err.Error()) > hranaMaxErrBody+64 {
			t.Errorf("error body was not truncated: len=%d", len(err.Error()))
		}
	})

	t.Run("redirect not followed", func(t *testing.T) {
		var targetHits atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer target.Close()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL+"?authToken=secret")
		err := db.PingContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "libsql http 302") {
			t.Fatalf("expected http 302 error, got %v", err)
		}
		if targetHits.Load() != 0 {
			t.Fatalf("redirect target was hit %d times, want 0", targetHits.Load())
		}
	})

	t.Run("pipeline error with message", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeHranaJSON(t, w, map[string]any{
				"baton": nil,
				"results": []any{
					map[string]any{
						"type":  "error",
						"error": map[string]string{"message": "SQLite error: duplicate column name: uid"},
					},
				},
			})
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL)
		_, err := db.ExecContext(context.Background(), "ALTER TABLE memories ADD COLUMN uid TEXT")
		if err == nil || !strings.Contains(err.Error(), "duplicate column") {
			t.Fatalf("expected duplicate column error, got %v", err)
		}
	})

	t.Run("pipeline error with nil error object", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeHranaJSON(t, w, map[string]any{
				"results": []any{map[string]any{"type": "error"}},
			})
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL)
		if _, err := db.ExecContext(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("expected error for type=error with nil error object")
		}
	})

	t.Run("empty pipeline results rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL)
		if _, err := db.ExecContext(context.Background(), "INSERT INTO t VALUES (1)"); err == nil {
			t.Fatal("expected error on empty pipeline results for Exec")
		}
		if _, err := db.QueryContext(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("expected error on empty pipeline results for Query")
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()

		db := openTestLibsql(t, srv.URL)
		if err := db.PingContext(context.Background()); err == nil {
			t.Fatal("expected json unmarshal error")
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		defer srv.Close()
		defer close(release)

		db := openTestLibsql(t, srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := db.PingContext(ctx); err == nil {
			t.Fatal("expected context timeout error")
		}
	})
}

func TestHranaPreparedStmtAndConcurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req hranaPipelineReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeHranaJSON(t, w, map[string]any{
			"baton": nil,
			"results": []any{
				map[string]any{
					"type": "ok",
					"response": map[string]any{
						"type": "execute",
						"result": map[string]any{
							"cols":               []map[string]string{{"name": "n"}},
							"rows":               [][]map[string]any{{{"type": "integer", "value": "99"}}},
							"affected_row_count": 1,
						},
					},
				},
				map[string]any{"type": "ok", "response": map[string]any{"type": "close"}},
			},
		})
	}))
	defer srv.Close()

	db := openTestLibsql(t, srv.URL)
	stmt, err := db.PrepareContext(context.Background(), "SELECT ?")
	if err != nil {
		t.Fatalf("PrepareContext: %v", err)
	}
	defer stmt.Close()

	// Prepared stmt respects canceled context.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stmt.ExecContext(canceledCtx, 1); err == nil {
		t.Fatal("expected canceled context error from stmt.ExecContext")
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var n int
			if err := stmt.QueryRowContext(context.Background(), i).Scan(&n); err != nil || n != 99 {
				t.Errorf("goroutine %d: n=%d err=%v", i, n, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestHranaBadConnDiscardedAfterFailedRollback(t *testing.T) {
	var failRollback atomic.Bool
	var closeCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req hranaPipelineReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		if len(req.Requests) == 1 && req.Requests[0].Type == "close" {
			closeCalls.Add(1)
			writeHranaJSON(t, w, map[string]any{
				"baton":   nil,
				"results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}},
			})
			return
		}
		if req.Requests[0].Stmt != nil && req.Requests[0].Stmt.SQL == "ROLLBACK" && failRollback.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
			return
		}
		nextBaton := "tx-baton"
		if len(req.Requests) > 1 && req.Requests[1].Type == "close" {
			nextBaton = ""
		}
		writeHranaJSON(t, w, map[string]any{
			"baton": nextBaton,
			"results": []any{
				map[string]any{"type": "ok", "response": map[string]any{"type": "execute", "result": map[string]any{"cols": []any{}, "rows": []any{}}}},
			},
		})
	}))
	defer srv.Close()

	db := openTestLibsql(t, srv.URL)
	db.SetMaxOpenConns(1)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	failRollback.Store(true)
	if err := tx.Rollback(); err == nil {
		t.Fatal("expected rollback error")
	}
	failRollback.Store(false)

	// Next Ping must succeed on a fresh connection (dirty conn discarded & closed).
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext after failed rollback: %v", err)
	}
	if closeCalls.Load() == 0 {
		t.Error("expected discarded connection Close() to send close request for leaked baton")
	}
}

func TestHranaClientReliesOnContextNotFixedTimeout(t *testing.T) {
	d := &hranaDriver{}
	c, err := d.Open("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	hc := c.(*hranaConn)
	if hc.client.Timeout != 0 {
		t.Errorf("http.Client.Timeout = %v, want 0 (rely on request context)", hc.client.Timeout)
	}
}
