// Package yamlite parses the subset of YAML used by GitHub Actions workflows,
// Dependabot files and lifeline.yml, with no third-party dependencies.
//
// Supported: block mappings and sequences (including "- key: value" items),
// plain/single-quoted/double-quoted scalars, literal (|) and folded (>) block
// scalars with chomping indicators, flow sequences [a, b] and flow mappings
// {a: b} (nested, possibly spanning several lines), comments and "---".
//
// Scalars are returned as strings (no int/bool conversion, so the key "on"
// stays "on" - unlike YAML 1.1 parsers), null as nil, mappings as
// map[string]any and sequences as []any. Anchors, aliases and tags are kept
// as literal text, which is enough for the checks Lifeline runs.
package yamlite

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse parses a YAML document.
func Parse(src string) (any, error) {
	p := &parser{}
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		p.lines = append(p.lines, newLine(raw, i+1))
	}
	p.skipBlank()
	if p.pos < len(p.lines) && (p.lines[p.pos].text == "---" || strings.HasPrefix(p.lines[p.pos].text, "--- ")) {
		p.pos++
	}
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	v, err := p.parseNode(p.lines[p.pos].indent)
	if err != nil {
		return nil, err
	}
	p.skipBlank()
	if p.pos < len(p.lines) && p.lines[p.pos].text != "..." && p.lines[p.pos].text != "---" {
		l := p.lines[p.pos]
		return v, fmt.Errorf("line %d: unexpected content %q", l.num, l.text)
	}
	return v, nil
}

// ParseMap parses a document whose top level must be a mapping.
func ParseMap(src string) (map[string]any, error) {
	v, err := Parse(src)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("top level is not a mapping")
	}
	return m, nil
}

type line struct {
	raw    string
	indent int
	text   string // content after indentation, comments removed, right-trimmed
	num    int
}

func newLine(raw string, num int) line {
	indent := 0
	for indent < len(raw) && raw[indent] == ' ' {
		indent++
	}
	body := raw[indent:]
	if strings.HasPrefix(body, "\t") {
		body = strings.TrimLeft(body, "\t")
	}
	return line{raw: raw, indent: indent, text: strings.TrimRight(stripComment(body), " \t"), num: num}
}

// stripComment removes a trailing "# comment" that is outside quotes.
func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inD:
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

type parser struct {
	lines []line
	pos   int
}

func (p *parser) skipBlank() {
	for p.pos < len(p.lines) && p.lines[p.pos].text == "" {
		p.pos++
	}
}

func (p *parser) peek() (line, bool) {
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return line{}, false
	}
	return p.lines[p.pos], true
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

// splitKey returns key, rest, ok if t is "key: rest" or "key:" (outside quotes/brackets).
func splitKey(t string) (string, string, bool) {
	if t == "" || t[0] == '[' || t[0] == '{' || t[0] == '|' || t[0] == '>' {
		return "", "", false
	}
	inS, inD, depth := false, false, 0
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c == '\\' && inD:
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ':' && depth == 0 && (i == len(t)-1 || t[i+1] == ' ' || t[i+1] == '\t'):
			key := strings.TrimSpace(t[:i])
			if key == "" {
				return "", "", false
			}
			if uq, err := unquote(key); err == nil {
				key = uq
			}
			return key, strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

func (p *parser) parseNode(indent int) (any, error) {
	l, ok := p.peek()
	if !ok || l.indent < indent {
		return nil, nil
	}
	if isSeqItem(l.text) {
		return p.parseSeq(l.indent)
	}
	if _, _, ok := splitKey(l.text); ok {
		return p.parseMap(l.indent)
	}
	p.pos++
	return p.inlineValue(l, l.text, l.indent-1)
}

func (p *parser) parseMap(indent int) (any, error) {
	m := map[string]any{}
	for {
		l, ok := p.peek()
		if !ok || l.indent != indent || isSeqItem(l.text) {
			break
		}
		key, rest, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected 'key: value', got %q", l.num, l.text)
		}
		p.pos++
		if rest == "" {
			next, ok := p.peek()
			switch {
			case ok && next.indent > indent:
				v, err := p.parseNode(next.indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case ok && next.indent == indent && isSeqItem(next.text):
				// "key:\n- item" with the dash at the same indentation is valid YAML
				v, err := p.parseSeq(indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			default:
				m[key] = nil
			}
			continue
		}
		v, err := p.inlineValue(l, rest, indent)
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
	return m, nil
}

func (p *parser) parseSeq(indent int) (any, error) {
	out := []any{}
	for {
		l, ok := p.peek()
		if !ok || l.indent != indent || !isSeqItem(l.text) {
			break
		}
		rest := strings.TrimLeft(strings.TrimPrefix(l.text, "-"), " ")
		if rest == "" {
			p.pos++
			next, ok := p.peek()
			if ok && next.indent > indent {
				v, err := p.parseNode(next.indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		offset := len(l.text) - len(rest)
		if _, _, isKey := splitKey(rest); isKey || isSeqItem(rest) {
			// Re-read this line as if the dash were spaces: "- a: 1" -> "  a: 1"
			p.lines[p.pos].indent = indent + offset
			p.lines[p.pos].text = rest
			v, err := p.parseNode(indent + offset)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.pos++
		v, err := p.inlineValue(l, rest, indent)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// inlineValue parses a value that starts on the current line. parentIndent is
// the indentation of the owning key or dash; continuation lines must be deeper.
func (p *parser) inlineValue(l line, v string, parentIndent int) (any, error) {
	switch {
	case strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">"):
		return p.blockScalar(v, parentIndent)
	case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{"):
		text := v
		for !balanced(text) && p.pos < len(p.lines) {
			text += " " + strings.TrimSpace(p.lines[p.pos].text)
			p.pos++
		}
		fp := &flowParser{s: text}
		out, err := fp.value()
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", l.num, err)
		}
		return out, nil
	case strings.HasPrefix(v, "\"") || strings.HasPrefix(v, "'"):
		s, err := unquote(v)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", l.num, err)
		}
		return s, nil
	}
	// plain scalar, possibly continued on deeper lines
	parts := []string{v}
	for {
		next, ok := p.peek()
		if !ok || next.indent <= parentIndent || isSeqItem(next.text) {
			break
		}
		if _, _, isKey := splitKey(next.text); isKey {
			break
		}
		parts = append(parts, next.text)
		p.pos++
	}
	return plain(strings.Join(parts, " ")), nil
}

func plain(s string) any {
	switch s {
	case "~", "null", "Null", "NULL":
		return nil
	}
	return s
}

func (p *parser) blockScalar(header string, parentIndent int) (any, error) {
	folded := header[0] == '>'
	chomp := "clip"
	explicit := 0
	for _, c := range header[1:] {
		switch {
		case c == '-':
			chomp = "strip"
		case c == '+':
			chomp = "keep"
		case c >= '1' && c <= '9':
			explicit = int(c - '0')
		}
	}
	var lines []string
	contentIndent := -1
	if explicit > 0 {
		contentIndent = parentIndent + explicit
		if parentIndent < 0 {
			contentIndent = explicit
		}
	}
	for p.pos < len(p.lines) {
		raw := p.lines[p.pos].raw
		trimmed := strings.TrimRight(raw, " \t")
		if trimmed == "" {
			lines = append(lines, "")
			p.pos++
			continue
		}
		ind := len(raw) - len(strings.TrimLeft(raw, " "))
		if ind <= parentIndent {
			break
		}
		if contentIndent < 0 {
			contentIndent = ind
		}
		if ind < contentIndent {
			break
		}
		lines = append(lines, strings.TrimRight(raw[contentIndent:], "\r"))
		p.pos++
	}
	// trailing blank lines belong to chomping, not content
	trailing := 0
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
		trailing++
	}
	var body string
	if folded {
		var b strings.Builder
		for i, ln := range lines {
			switch {
			case i == 0:
				b.WriteString(ln)
			case ln == "" || strings.HasPrefix(ln, " ") || lines[i-1] == "" || strings.HasPrefix(lines[i-1], " "):
				// folding only joins two "normal" lines; more-indented lines keep their breaks
				b.WriteString("\n" + ln)
			default:
				b.WriteString(" " + ln)
			}
		}
		body = b.String()
	} else {
		body = strings.Join(lines, "\n")
	}
	switch chomp {
	case "strip":
	case "keep":
		body += "\n" + strings.Repeat("\n", trailing)
	default:
		if len(lines) > 0 {
			body += "\n"
		}
	}
	return body, nil
}

func balanced(s string) bool {
	depth := 0
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inD:
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth <= 0
}

func unquote(s string) (string, error) {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var b strings.Builder
		in := s[1 : len(s)-1]
		for i := 0; i < len(in); i++ {
			c := in[i]
			if c != '\\' || i+1 >= len(in) {
				b.WriteByte(c)
				continue
			}
			i++
			switch in[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case '"', '\\', '/':
				b.WriteByte(in[i])
			case 'u':
				if i+4 < len(in) {
					if r, err := strconv.ParseUint(in[i+1:i+5], 16, 32); err == nil {
						b.WriteRune(rune(r))
						i += 4
						continue
					}
				}
				b.WriteString("\\u")
			default:
				b.WriteByte('\\')
				b.WriteByte(in[i])
			}
		}
		return b.String(), nil
	}
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		return "", fmt.Errorf("unterminated quoted string %q", s)
	}
	return s, nil
}

// ---------------------------------------------------------------- flow style

type flowParser struct {
	s string
	i int
}

func (f *flowParser) ws() {
	for f.i < len(f.s) && (f.s[f.i] == ' ' || f.s[f.i] == '\t') {
		f.i++
	}
}

func (f *flowParser) value() (any, error) {
	f.ws()
	if f.i >= len(f.s) {
		return nil, fmt.Errorf("unexpected end of flow collection")
	}
	switch f.s[f.i] {
	case '[':
		f.i++
		out := []any{}
		for {
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ']' {
				f.i++
				return out, nil
			}
			v, err := f.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
				continue
			}
			if f.i < len(f.s) && f.s[f.i] == ']' {
				f.i++
				return out, nil
			}
			return nil, fmt.Errorf("expected ',' or ']' in %q", f.s)
		}
	case '{':
		f.i++
		out := map[string]any{}
		for {
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == '}' {
				f.i++
				return out, nil
			}
			k, err := f.scalar(":,}")
			if err != nil {
				return nil, err
			}
			f.ws()
			var v any
			if f.i < len(f.s) && f.s[f.i] == ':' {
				f.i++
				v, err = f.value()
				if err != nil {
					return nil, err
				}
			}
			key, _ := k.(string)
			out[key] = v
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
				continue
			}
			if f.i < len(f.s) && f.s[f.i] == '}' {
				f.i++
				return out, nil
			}
			return nil, fmt.Errorf("expected ',' or '}' in %q", f.s)
		}
	default:
		return f.scalar(",]}")
	}
}

func (f *flowParser) scalar(stops string) (any, error) {
	f.ws()
	if f.i < len(f.s) && (f.s[f.i] == '"' || f.s[f.i] == '\'') {
		q := f.s[f.i]
		j := f.i + 1
		for j < len(f.s) {
			if q == '"' && f.s[j] == '\\' {
				j += 2
				continue
			}
			if f.s[j] == q {
				if q == '\'' && j+1 < len(f.s) && f.s[j+1] == '\'' {
					j += 2
					continue
				}
				break
			}
			j++
		}
		if j >= len(f.s) {
			return nil, fmt.Errorf("unterminated string in %q", f.s)
		}
		s, err := unquote(f.s[f.i : j+1])
		f.i = j + 1
		return s, err
	}
	start := f.i
	for f.i < len(f.s) {
		c := f.s[f.i]
		if c == ':' && strings.ContainsRune(stops, ':') && (f.i+1 >= len(f.s) || f.s[f.i+1] == ' ') {
			break
		}
		if c != ':' && strings.ContainsRune(stops, rune(c)) {
			break
		}
		f.i++
	}
	return plain(strings.TrimSpace(f.s[start:f.i])), nil
}
