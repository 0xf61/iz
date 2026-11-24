package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	hranaMaxRespBytes   = 64 << 20
	hranaMaxErrBody     = 512
	hranaCleanupTimeout = 5 * time.Second
)

func init() {
	sql.Register("libsql", &hranaDriver{})
}

type hranaDriver struct{}

func (d *hranaDriver) Open(dsn string) (driver.Conn, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		// Do not include raw dsn in error: it may contain authToken.
		return nil, errors.New("libsql: invalid URL")
	}
	q := u.Query()
	token := q.Get("authToken")
	q.Del("authToken")
	tlsParam := q.Get("tls")
	q.Del("tls")

	switch u.Scheme {
	case "libsql":
		if tlsParam == "false" || tlsParam == "0" {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	case "http", "https":
	default:
		return nil, fmt.Errorf("libsql: unsupported URL scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("libsql: missing host in URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v2/pipeline"
	u.RawQuery = q.Encode()
	u.Fragment = ""
	endpoint := u.String()

	return &hranaConn{
		baseEndpoint: endpoint,
		endpoint:     endpoint,
		token:        token,
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type hranaConn struct {
	baseEndpoint string
	endpoint     string
	token        string
	client       *http.Client
	baton        string
	inTx         bool
	bad          bool
}

var (
	_ driver.Conn               = (*hranaConn)(nil)
	_ driver.Pinger             = (*hranaConn)(nil)
	_ driver.ExecerContext      = (*hranaConn)(nil)
	_ driver.QueryerContext     = (*hranaConn)(nil)
	_ driver.ConnBeginTx        = (*hranaConn)(nil)
	_ driver.ConnPrepareContext = (*hranaConn)(nil)
	_ driver.SessionResetter    = (*hranaConn)(nil)
	_ driver.Validator          = (*hranaConn)(nil)
	_ driver.Stmt               = (*hranaStmt)(nil)
	_ driver.StmtExecContext    = (*hranaStmt)(nil)
	_ driver.StmtQueryContext   = (*hranaStmt)(nil)
)

func (c *hranaConn) IsValid() bool {
	return !c.bad && !c.inTx
}

func (c *hranaConn) ResetSession(ctx context.Context) error {
	if c.bad || c.inTx {
		return driver.ErrBadConn
	}
	if c.baton != "" {
		cctx, cancel := context.WithTimeout(ctx, hranaCleanupTimeout)
		_, err := c.pipeline(cctx, []hranaReq{{Type: "close"}})
		cancel()
		c.baton = ""
		c.endpoint = c.baseEndpoint
		if err != nil {
			return driver.ErrBadConn
		}
	}
	return nil
}

func (c *hranaConn) Close() error {
	if c.baton != "" {
		c.bad = false
		ctx, cancel := context.WithTimeout(context.Background(), hranaCleanupTimeout)
		_, _ = c.pipeline(ctx, []hranaReq{{Type: "close"}})
		cancel()
		c.baton = ""
	}
	c.bad = true
	c.inTx = false
	c.endpoint = c.baseEndpoint
	return nil
}

func (c *hranaConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *hranaConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, fmt.Errorf("libsql: unsupported isolation level %d", opts.Isolation)
	}
	beginSQL := "BEGIN IMMEDIATE"
	if opts.ReadOnly {
		beginSQL = "BEGIN"
	}
	if _, err := c.execStmt(ctx, beginSQL, nil, false); err != nil {
		return nil, err
	}
	c.inTx = true
	return &hranaTx{conn: c, ctx: ctx}, nil
}

func (c *hranaConn) Prepare(query string) (driver.Stmt, error) {
	return &hranaStmt{conn: c, query: query}, nil
}

func (c *hranaConn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	return &hranaStmt{conn: c, query: query}, nil
}

func (c *hranaConn) Ping(ctx context.Context) error {
	_, err := c.exec(ctx, "SELECT 1", nil)
	return err
}

func (c *hranaConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.exec(ctx, query, args)
}

func (c *hranaConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.query(ctx, query, args)
}

type hranaTx struct {
	conn *hranaConn
	ctx  context.Context
}

func (tx *hranaTx) Commit() error {
	return tx.conn.finishTx(tx.ctx, "COMMIT")
}

func (tx *hranaTx) Rollback() error {
	// Detach cancellation so server-side ROLLBACK + stream close still run
	// when tx.ctx was canceled mid-transaction.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(tx.ctx), hranaCleanupTimeout)
	defer cancel()
	return tx.conn.finishTx(ctx, "ROLLBACK")
}

func (c *hranaConn) finishTx(ctx context.Context, sqlStmt string) error {
	_, err := c.execStmt(ctx, sqlStmt, nil, true)
	c.inTx = false
	if err != nil {
		if c.baton != "" {
			c.bad = true
		}
		return err
	}
	c.baton = ""
	c.endpoint = c.baseEndpoint
	return nil
}

type hranaStmt struct {
	conn  *hranaConn
	query string
}

func (s *hranaStmt) Close() error  { return nil }
func (s *hranaStmt) NumInput() int { return -1 }

func (s *hranaStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.conn.exec(context.Background(), s.query, namedValues(args))
}

func (s *hranaStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.conn.exec(ctx, s.query, args)
}

func (s *hranaStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.conn.query(context.Background(), s.query, namedValues(args))
}

func (s *hranaStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.conn.query(ctx, s.query, args)
}

func namedValues(args []driver.Value) []driver.NamedValue {
	nv := make([]driver.NamedValue, len(args))
	for i, v := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return nv
}

type hranaReq struct {
	Type string            `json:"type"`
	Stmt *hranaStmtPayload `json:"stmt,omitempty"`
}

type hranaStmtPayload struct {
	SQL       string          `json:"sql"`
	Args      []hranaValue    `json:"args,omitempty"`
	NamedArgs []hranaNamedArg `json:"named_args,omitempty"`
}

type hranaNamedArg struct {
	Name  string     `json:"name"`
	Value hranaValue `json:"value"`
}

// hranaValue uses pointer values for Value and Base64 so zero values ("", 0.0,
// empty blob base64) are marshaled rather than dropped by omitempty, while null
// values omit both fields.
type hranaValue struct {
	Type   string  `json:"type"`
	Value  any     `json:"value,omitempty"`
	Base64 *string `json:"base64,omitempty"`
}

type hranaPipelineReq struct {
	Baton    string     `json:"baton,omitempty"`
	Requests []hranaReq `json:"requests"`
}

type hranaPipelineResp struct {
	Baton   string `json:"baton"`
	BaseURL string `json:"base_url"`
	Results []struct {
		Type     string `json:"type"`
		Response *struct {
			Type   string `json:"type"`
			Result struct {
				Cols []struct {
					Name string `json:"name"`
				} `json:"cols"`
				Rows             [][]hranaRawValue `json:"rows"`
				AffectedRowCount int64             `json:"affected_row_count"`
				LastInsertRowid  json.RawMessage   `json:"last_insert_rowid"`
			} `json:"result"`
		} `json:"response"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
}

type hranaRawValue struct {
	Type   string          `json:"type"`
	Value  json.RawMessage `json:"value"`
	Base64 string          `json:"base64"`
}

func encodeValue(val any) (hranaValue, error) {
	switch v := val.(type) {
	case nil:
		return hranaValue{Type: "null"}, nil
	case int64:
		s := strconv.FormatInt(v, 10)
		return hranaValue{Type: "integer", Value: &s}, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return hranaValue{}, fmt.Errorf("libsql: unsupported non-finite float %v", v)
		}
		f := v
		return hranaValue{Type: "float", Value: &f}, nil
	case bool:
		s := "0"
		if v {
			s = "1"
		}
		return hranaValue{Type: "integer", Value: &s}, nil
	case string:
		s := v
		return hranaValue{Type: "text", Value: &s}, nil
	case []byte:
		if v == nil {
			return hranaValue{Type: "null"}, nil
		}
		b64 := base64.StdEncoding.EncodeToString(v)
		return hranaValue{Type: "blob", Base64: &b64}, nil
	case time.Time:
		s := v.UTC().Format(time.RFC3339Nano)
		return hranaValue{Type: "text", Value: &s}, nil
	default:
		return hranaValue{}, fmt.Errorf("libsql: unsupported arg type %T", v)
	}
}

func encodeArgs(args []driver.NamedValue) ([]hranaValue, []hranaNamedArg, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	var pos []hranaValue
	var named []hranaNamedArg
	for _, a := range args {
		hv, err := encodeValue(a.Value)
		if err != nil {
			return nil, nil, err
		}
		if a.Name != "" {
			named = append(named, hranaNamedArg{Name: a.Name, Value: hv})
		} else {
			pos = append(pos, hv)
		}
	}
	return pos, named, nil
}

func (c *hranaConn) applyBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("libsql: invalid server base_url")
	}
	if u.User != nil {
		return errors.New("libsql: refusing userinfo in server base_url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("libsql: unsupported server base_url scheme %q", u.Scheme)
	}
	base, err := url.Parse(c.baseEndpoint)
	if err != nil || base.Host == "" {
		return errors.New("libsql: invalid base endpoint")
	}
	if base.Scheme == "https" && u.Scheme != "https" {
		return errors.New("libsql: refusing https to http downgrade in base_url")
	}
	if !sameHostOrDomain(base.Hostname(), u.Hostname()) {
		return fmt.Errorf("libsql: refusing untrusted base_url host %q", u.Hostname())
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v2/pipeline"
	u.RawQuery = ""
	u.Fragment = ""
	c.endpoint = u.String()
	return nil
}

// sameHostOrDomain reports whether target shares the same host or registrable
// parent domain as base (blocking cross-domain SSRF and Bearer token leaks).
func sameHostOrDomain(base, target string) bool {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	if base == "" || target == "" {
		return false
	}
	if base == target {
		return true
	}
	if net.ParseIP(base) != nil || net.ParseIP(target) != nil {
		return false
	}
	bd, td := parentDomain(base), parentDomain(target)
	return bd != "" && bd == td
}

func parentDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	n := 2
	if len(parts) >= 3 && len(parts[len(parts)-1]) == 2 {
		switch parts[len(parts)-2] {
		case "co", "com", "net", "org", "gov", "edu", "ac", "mil":
			n = 3
		}
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

func (c *hranaConn) pipeline(ctx context.Context, reqs []hranaReq) (*hranaPipelineResp, error) {
	if c.bad {
		return nil, driver.ErrBadConn
	}
	body, err := json.Marshal(hranaPipelineReq{Baton: c.baton, Requests: reqs})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, hranaMaxRespBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > hranaMaxRespBytes {
		return nil, fmt.Errorf("libsql: response exceeds %d bytes", hranaMaxRespBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > hranaMaxErrBody {
			msg = msg[:hranaMaxErrBody] + "..."
		}
		if !c.inTx {
			c.baton = ""
			c.endpoint = c.baseEndpoint
		}
		return nil, fmt.Errorf("libsql http %d: %s", resp.StatusCode, msg)
	}
	var out hranaPipelineResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	c.baton = out.Baton
	if out.Baton == "" {
		c.endpoint = c.baseEndpoint
	} else if out.BaseURL != "" {
		if err := c.applyBaseURL(out.BaseURL); err != nil {
			return nil, err
		}
	}
	for _, r := range out.Results {
		if r.Type == "error" {
			msg := "hrana pipeline error"
			if r.Error != nil && r.Error.Message != "" {
				msg = r.Error.Message
			}
			return nil, errors.New(msg)
		}
	}
	return &out, nil
}

func (c *hranaConn) exec(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.execStmt(ctx, query, args, !c.inTx)
}

func (c *hranaConn) execStmt(ctx context.Context, query string, args []driver.NamedValue, closeStream bool) (driver.Result, error) {
	hargs, named, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	reqs := []hranaReq{{
		Type: "execute",
		Stmt: &hranaStmtPayload{SQL: query, Args: hargs, NamedArgs: named},
	}}
	if closeStream {
		reqs = append(reqs, hranaReq{Type: "close"})
	}
	resp, err := c.pipeline(ctx, reqs)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 || resp.Results[0].Response == nil {
		return nil, errors.New("libsql: empty pipeline response")
	}
	res := resp.Results[0].Response.Result
	return hranaResult{lastID: parseRowID(res.LastInsertRowid), affected: res.AffectedRowCount}, nil
}

func (c *hranaConn) query(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	hargs, named, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	reqs := []hranaReq{{
		Type: "execute",
		Stmt: &hranaStmtPayload{SQL: query, Args: hargs, NamedArgs: named},
	}}
	if !c.inTx {
		reqs = append(reqs, hranaReq{Type: "close"})
	}
	resp, err := c.pipeline(ctx, reqs)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 || resp.Results[0].Response == nil {
		return nil, errors.New("libsql: empty pipeline response")
	}
	res := resp.Results[0].Response.Result
	cols := make([]string, len(res.Cols))
	for i, col := range res.Cols {
		cols[i] = col.Name
	}
	return &hranaRows{cols: cols, rows: res.Rows}, nil
}

func parseRowID(raw json.RawMessage) int64 {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		n, _ := strconv.ParseInt(s, 10, 64)
		return n
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	return 0
}

type hranaResult struct {
	lastID   int64
	affected int64
}

func (r hranaResult) LastInsertId() (int64, error) { return r.lastID, nil }
func (r hranaResult) RowsAffected() (int64, error) { return r.affected, nil }

type hranaRows struct {
	cols []string
	rows [][]hranaRawValue
	idx  int
}

func (r *hranaRows) Columns() []string { return r.cols }
func (r *hranaRows) Close() error {
	r.rows = nil
	r.idx = 0
	return nil
}

func (r *hranaRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	r.idx++
	for i := range dest {
		if i >= len(row) {
			dest[i] = nil
			continue
		}
		v, err := decodeValue(row[i])
		if err != nil {
			return err
		}
		dest[i] = v
	}
	return nil
}

func decodeValue(rv hranaRawValue) (driver.Value, error) {
	switch rv.Type {
	case "null":
		return nil, nil
	case "integer":
		var s string
		if err := json.Unmarshal(rv.Value, &s); err == nil {
			return strconv.ParseInt(s, 10, 64)
		}
		var n int64
		if err := json.Unmarshal(rv.Value, &n); err != nil {
			return nil, err
		}
		return n, nil
	case "float":
		if len(rv.Value) == 0 || bytes.Equal(rv.Value, []byte("null")) {
			return nil, errors.New("libsql: missing float value")
		}
		var f float64
		if err := json.Unmarshal(rv.Value, &f); err != nil {
			return nil, err
		}
		return f, nil
	case "text":
		if len(rv.Value) == 0 || bytes.Equal(rv.Value, []byte("null")) {
			return nil, errors.New("libsql: missing text value")
		}
		var s string
		if err := json.Unmarshal(rv.Value, &s); err != nil {
			return nil, err
		}
		return s, nil
	case "blob":
		if strings.ContainsRune(rv.Base64, '=') {
			return base64.StdEncoding.DecodeString(rv.Base64)
		}
		return base64.RawStdEncoding.DecodeString(rv.Base64)
	default:
		return nil, fmt.Errorf("unknown hrana value type %q", rv.Type)
	}
}
