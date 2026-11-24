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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	sql.Register("libsql", &hranaDriver{})
}

type hranaDriver struct{}

func (d *hranaDriver) Open(dsn string) (driver.Conn, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	token := q.Get("authToken")
	q.Del("authToken")
	tlsParam := q.Get("tls")
	q.Del("tls")

	switch u.Scheme {
	case "libsql", "wss":
		if tlsParam == "false" || tlsParam == "0" {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	case "ws":
		u.Scheme = "http"
	}
	u.RawQuery = q.Encode()
	endpoint := strings.TrimRight(u.String(), "/") + "/v2/pipeline"

	return &hranaConn{
		endpoint: endpoint,
		token:    token,
		client:   &http.Client{Timeout: 60 * time.Second},
	}, nil
}

type hranaConn struct {
	endpoint string
	token    string
	client   *http.Client
	baton    string
}

func (c *hranaConn) Close() error {
	if c.baton != "" {
		_, _ = c.pipeline(context.Background(), []hranaReq{{Type: "close"}})
		c.baton = ""
	}
	return nil
}

func (c *hranaConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *hranaConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if _, err := c.exec(ctx, "BEGIN", nil); err != nil {
		return nil, err
	}
	return &hranaTx{conn: c, ctx: ctx}, nil
}

func (c *hranaConn) Prepare(query string) (driver.Stmt, error) {
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
	_, err := tx.conn.exec(tx.ctx, "COMMIT", nil)
	return err
}

func (tx *hranaTx) Rollback() error {
	_, err := tx.conn.exec(tx.ctx, "ROLLBACK", nil)
	return err
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

func (s *hranaStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.conn.query(context.Background(), s.query, namedValues(args))
}

func namedValues(args []driver.Value) []driver.NamedValue {
	nv := make([]driver.NamedValue, len(args))
	for i, v := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return nv
}

type hranaReq struct {
	Type string     `json:"type"`
	Stmt *hranaStmtPayload `json:"stmt,omitempty"`
}

type hranaStmtPayload struct {
	SQL  string       `json:"sql"`
	Args []hranaValue `json:"args,omitempty"`
}

type hranaValue struct {
	Type   string `json:"type"`
	Value  any    `json:"value,omitempty"`
	Base64 string `json:"base64,omitempty"`
}

type hranaPipelineReq struct {
	Baton    string     `json:"baton,omitempty"`
	Requests []hranaReq `json:"requests"`
}

type hranaPipelineResp struct {
	Baton   string `json:"baton"`
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
				LastInsertRowid  string            `json:"last_insert_rowid"`
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

func encodeArgs(args []driver.NamedValue) ([]hranaValue, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]hranaValue, len(args))
	for i, a := range args {
		switch v := a.Value.(type) {
		case nil:
			out[i] = hranaValue{Type: "null"}
		case int64:
			out[i] = hranaValue{Type: "integer", Value: strconv.FormatInt(v, 10)}
		case float64:
			out[i] = hranaValue{Type: "float", Value: v}
		case bool:
			if v {
				out[i] = hranaValue{Type: "integer", Value: "1"}
			} else {
				out[i] = hranaValue{Type: "integer", Value: "0"}
			}
		case string:
			out[i] = hranaValue{Type: "text", Value: v}
		case []byte:
			out[i] = hranaValue{Type: "blob", Base64: base64.StdEncoding.EncodeToString(v)}
		default:
			return nil, fmt.Errorf("unsupported arg type %T", v)
		}
	}
	return out, nil
}

func (c *hranaConn) pipeline(ctx context.Context, reqs []hranaReq) (*hranaPipelineResp, error) {
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("libsql http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out hranaPipelineResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	c.baton = out.Baton
	for _, r := range out.Results {
		if r.Type == "error" && r.Error != nil {
			return nil, errors.New(r.Error.Message)
		}
	}
	return &out, nil
}

func (c *hranaConn) exec(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	hargs, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	resp, err := c.pipeline(ctx, []hranaReq{{
		Type: "execute",
		Stmt: &hranaStmtPayload{SQL: query, Args: hargs},
	}})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 || resp.Results[0].Response == nil {
		return driver.RowsAffected(0), nil
	}
	res := resp.Results[0].Response.Result
	lastID, _ := strconv.ParseInt(res.LastInsertRowid, 10, 64)
	return hranaResult{lastID: lastID, affected: res.AffectedRowCount}, nil
}

func (c *hranaConn) query(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	hargs, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	resp, err := c.pipeline(ctx, []hranaReq{{
		Type: "execute",
		Stmt: &hranaStmtPayload{SQL: query, Args: hargs},
	}})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 || resp.Results[0].Response == nil {
		return &hranaRows{}, nil
	}
	res := resp.Results[0].Response.Result
	cols := make([]string, len(res.Cols))
	for i, col := range res.Cols {
		cols[i] = col.Name
	}
	return &hranaRows{cols: cols, rows: res.Rows}, nil
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
func (r *hranaRows) Close() error      { return nil }

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
		var f float64
		if err := json.Unmarshal(rv.Value, &f); err != nil {
			return nil, err
		}
		return f, nil
	case "text":
		var s string
		if err := json.Unmarshal(rv.Value, &s); err != nil {
			return nil, err
		}
		return s, nil
	case "blob":
		return base64.StdEncoding.DecodeString(rv.Base64)
	default:
		return nil, fmt.Errorf("unknown hrana value type %q", rv.Type)
	}
}
