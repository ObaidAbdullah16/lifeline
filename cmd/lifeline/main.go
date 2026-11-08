// Command lifeline scores how well an open-source project's operations would
// survive a bad day: domains and TLS, access bus factor, CI hygiene, backups
// and cost runway.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/checks"
	"github.com/ObaidAbdullah16/lifeline/internal/manifest"
	"github.com/ObaidAbdullah16/lifeline/internal/report"
)

// version is set at build time: -ldflags "-X main.version=v0.3.0"
var version = "dev"

const usage = `Lifeline - operational-resilience scorecard

Usage:
  lifeline scan  [--repo owner/name] [--domain example.org] [--path .] [flags]
  lifeline batch --targets targets.txt --out results/
  lifeline checks
  lifeline version

Run "lifeline scan -h" for scan flags. Set GITHUB_TOKEN (or GH_TOKEN) for
higher API limits and for checks that need an organisation owner's view.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "scan":
		code, err = cmdScan(os.Args[2:], os.Stdout)
	case "batch":
		err = cmdBatch(os.Args[2:], os.Stdout)
	case "checks":
		cmdChecks(os.Stdout)
	case "version", "--version", "-v":
		fmt.Println("lifeline", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

type scanOpts struct {
	repo, domain, path, config, format, output   string
	jsonOut, mdOut, sarifOut, badgeOut, previous string
	htmlOut                                      string
	failUnder                                    float64
	timeout                                      time.Duration
}

func cmdScan(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var o scanOpts
	fs.StringVar(&o.repo, "repo", "", "GitHub repository owner/name")
	fs.StringVar(&o.domain, "domain", "", "project domain (default: lifeline.yml `domain:` or the repo homepage)")
	fs.StringVar(&o.path, "path", "", "local checkout to read workflows and lifeline.yml from (default: API)")
	fs.StringVar(&o.config, "config", "", "path to lifeline.yml (default: lifeline.yml or .github/lifeline.yml under --path)")
	fs.StringVar(&o.format, "format", "text", "stdout format: text, json, md, sarif, badge, html")
	fs.StringVar(&o.output, "o", "", "write the --format output to this file instead of stdout")
	fs.StringVar(&o.jsonOut, "json", "", "also write JSON to this file")
	fs.StringVar(&o.mdOut, "markdown", "", "also write Markdown to this file")
	fs.StringVar(&o.sarifOut, "sarif", "", "also write SARIF to this file")
	fs.StringVar(&o.badgeOut, "badge", "", "also write a shields.io endpoint badge JSON to this file")
	fs.StringVar(&o.htmlOut, "html", "", "also write a self-contained HTML report to this file")
	fs.StringVar(&o.previous, "previous", "", "previous JSON report, to show the change in score")
	fs.Float64Var(&o.failUnder, "fail-under", 0, "exit with code 1 when the score is below this value (0-10)")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Minute, "overall timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 2, nil
	}
	if !formats[o.format] {
		return 2, fmt.Errorf("unknown --format %q (use text, json, md, sarif, badge or html)", o.format)
	}
	rep, err := scan(o)
	if err != nil {
		return 1, err
	}
	if o.previous != "" {
		prev, err := readReport(o.previous)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: --previous %s ignored: %v\n", o.previous, err)
		} else {
			p := prev.Score
			d := float64(int((rep.Score-p)*10+sign(rep.Score-p)*0.5)) / 10
			rep.Previous, rep.Delta = &p, &d
		}
	}
	render := map[string]func() string{
		"text":  func() string { return report.Text(rep) },
		"json":  func() string { return report.JSON(rep) },
		"md":    func() string { return report.Markdown(rep) },
		"sarif": func() string { return report.SARIF(rep, checks.All()) },
		"badge": func() string { return report.Badge(rep) },
		"html":  func() string { return report.HTML(rep) },
	}
	f := render[o.format]
	if o.output != "" {
		if err := writeFile(o.output, f()); err != nil {
			return 1, err
		}
	} else {
		fmt.Fprintln(stdout, f())
	}
	for path, fn := range map[string]func() string{o.jsonOut: render["json"], o.mdOut: render["md"], o.sarifOut: render["sarif"], o.badgeOut: render["badge"], o.htmlOut: render["html"]} {
		if path != "" {
			if err := writeFile(path, fn()); err != nil {
				return 1, err
			}
		}
	}
	if o.failUnder > 0 && rep.Score < o.failUnder {
		fmt.Fprintf(os.Stderr, "score %.1f is below --fail-under %.1f\n", rep.Score, o.failUnder)
		return 1, nil
	}
	return 0, nil
}

var formats = map[string]bool{"text": true, "json": true, "md": true, "sarif": true, "badge": true, "html": true}

func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

func scan(o scanOpts) (*checks.Report, error) {
	if o.repo == "" && o.domain == "" && o.path == "" {
		return nil, errors.New("give at least one of --repo, --domain or --path")
	}
	if o.repo != "" && !repoRe.MatchString(o.repo) {
		return nil, fmt.Errorf("--repo must look like owner/name, got %q", o.repo)
	}
	m, err := manifest.Load(o.path, o.config)
	if err != nil {
		return nil, err
	}
	for _, w := range m.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	env := checks.NewEnv(ctx, m)
	return checks.Run(env, checks.Target{Repo: o.repo, Domain: o.domain, LocalPath: o.path}, version), nil
}

// repoRe accepts GitHub owner/name pairs and nothing that could change the
// API path (no "..", no extra slashes, no query characters).
var repoRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/(?:[A-Za-z0-9_.-]*[A-Za-z0-9_-][A-Za-z0-9_.-]*)$`)

func readReport(path string) (*checks.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r checks.Report
	return &r, json.Unmarshal(b, &r)
}

func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func cmdChecks(w io.Writer) {
	for _, c := range checks.All() {
		fmt.Fprintf(w, "%-11s w=%-2d %-20s %s\n", c.ID, c.Weight, c.Category, c.Title)
	}
}

// ------------------------------------------------------------------- batch

// cmdBatch scans many projects and writes per-project JSON plus an anonymised
// summary - the raw material for a "state of open-source operations" report.
func cmdBatch(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	targets := fs.String("targets", "", "file with one target per line: owner/name [domain]  (# comments allowed)")
	out := fs.String("out", "lifeline-batch", "output directory")
	names := fs.Bool("include-names", false, "list project names in the summary (default: anonymised)")
	pause := fs.Duration("pause", 2*time.Second, "pause between projects (API politeness)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targets == "" {
		return errors.New("--targets is required")
	}
	if os.Getenv("GITHUB_TOKEN") == "" && os.Getenv("GH_TOKEN") == "" {
		fmt.Fprintln(os.Stderr, "warning: no GITHUB_TOKEN - GitHub allows 60 unauthenticated API requests an hour, about two projects' worth")
	}
	f, err := os.Open(*targets)
	if err != nil {
		return err
	}
	defer f.Close()
	var reps []*checks.Report
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		o := scanOpts{timeout: 2 * time.Minute}
		if strings.Contains(fields[0], "/") {
			o.repo = fields[0]
			if len(fields) > 1 {
				o.domain = fields[1]
			}
		} else {
			o.domain = fields[0]
		}
		rep, err := scan(o)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", line, err)
			continue
		}
		reps = append(reps, rep)
		name := strings.NewReplacer("/", "__", ".", "_").Replace(fields[0])
		if err := writeFile(filepath.Join(*out, "projects", name+".json"), report.JSON(rep)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%-45s %.1f  coverage %.0f%%\n", fields[0], rep.Score, rep.Coverage*100)
		time.Sleep(*pause)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return writeFile(filepath.Join(*out, "SUMMARY.md"), summary(reps, *names))
}

// minSummaryCoverage is the coverage a scan needs to count in the median.
const minSummaryCoverage = 0.5

func summary(reps []*checks.Report, withNames bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Lifeline batch summary\n\n%d projects scanned on %s.\n\n", len(reps), time.Now().UTC().Format("2006-01-02"))
	if len(reps) == 0 {
		return b.String()
	}
	// A score computed from a few checks (rate limit, private data) is not
	// comparable with the others, so the headline numbers use well-covered scans only.
	scores := make([]float64, 0, len(reps))
	for _, r := range reps {
		if r.Coverage >= minSummaryCoverage {
			scores = append(scores, r.Score)
		}
	}
	if excluded := len(reps) - len(scores); excluded > 0 {
		fmt.Fprintf(&b, "%d project(s) with coverage below %.0f%% are left out of the score statistics.\n\n", excluded, minSummaryCoverage*100)
	}
	if len(scores) > 0 {
		sort.Float64s(scores)
		median := scores[len(scores)/2]
		if len(scores)%2 == 0 {
			median = (scores[len(scores)/2-1] + scores[len(scores)/2]) / 2
		}
		fmt.Fprintf(&b, "Median score **%.1f/10** (min %.1f, max %.1f) over %d project(s).\n\n", median, scores[0], scores[len(scores)-1], len(scores))
	}
	b.WriteString("| Check | Pass | Warn | Fail | Not evaluated | Fail rate* |\n|---|---|---|---|---|---|\n")
	for _, c := range checks.All() {
		counts := map[checks.Status]int{}
		for _, r := range reps {
			for _, res := range r.Results {
				if res.ID == c.ID {
					counts[res.Status]++
				}
			}
		}
		evaluated := counts[checks.Pass] + counts[checks.Warn] + counts[checks.Fail]
		rate := "-"
		if evaluated > 0 {
			rate = fmt.Sprintf("%.0f%%", 100*float64(counts[checks.Fail])/float64(evaluated))
		}
		fmt.Fprintf(&b, "| %s %s | %d | %d | %d | %d | %s |\n", c.ID, c.Title, counts[checks.Pass], counts[checks.Warn], counts[checks.Fail], counts[checks.Skip]+counts[checks.Error], rate)
	}
	b.WriteString("\n\\* of projects where the check could be evaluated.\n")
	if withNames {
		b.WriteString("\n## Projects\n\n| Project | Score | Coverage |\n|---|---|---|\n")
		for _, r := range reps {
			name := r.Repo
			if name == "" {
				name = r.Domain
			}
			fmt.Fprintf(&b, "| %s | %.1f | %.0f%% |\n", name, r.Score, r.Coverage*100)
		}
	}
	return b.String()
}
