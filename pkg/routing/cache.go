package routing

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"

	"github.com/brawler2011/tuncli/pkg/storage"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/sys/unix"
)

const MaxSize = 16 << 20
const FreshFor = 24 * time.Hour

type Record struct {
	URL     string    `json:"url"`
	SHA256  string    `json:"sha256"`
	Checked time.Time `json:"checked"`
}
type Cache struct {
	Dir     string
	Client  *http.Client
	BaseURL string
}

func NewCache(dir string) *Cache {
	return &Cache{Dir: dir, BaseURL: BaseURL, Client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("HTTPS required")
		}
		return nil
	}}}
}
func (c *Cache) Status(id string) (Record, error) {
	var r Record
	b, err := os.ReadFile(filepath.Join(c.Dir, id+".json"))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	return r, err
}
func (c *Cache) path(r Record) string { return filepath.Join(c.Dir, r.SHA256+".srs") }
func (c *Cache) verified(id string) (Record, error) {
	r, err := c.Status(id)
	if err != nil {
		return r, err
	}
	hash, err := hex.DecodeString(r.SHA256)
	if err != nil || len(hash) != 32 {
		return r, errors.New("invalid cache hash")
	}
	p, _ := Find(id)
	if r.URL != c.BaseURL+p.File {
		return r, errors.New("cache source changed")
	}
	b, err := os.ReadFile(c.path(r))
	if err != nil {
		return r, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != r.SHA256 {
		return r, errors.New("cache checksum mismatch")
	}
	return r, ValidateSRS(b)
}

// ValidateSRS fully decodes with the pinned sing-box reader and accepts only
// domain predicates, so DNS and traffic can use the same rule set.
func ValidateSRS(b []byte) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("malformed SRS: %v", p)
		}
	}()
	if len(b) < 4 || len(b) > MaxSize {
		return errors.New("invalid SRS size")
	}
	// Bound the expanded stream before invoking the binary decoder.
	z, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return err
	}
	expanded, readErr := io.ReadAll(io.LimitReader(z, MaxSize+1))
	closeErr := z.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(expanded) > MaxSize {
		return errors.New("expanded SRS too large")
	}
	if err = guardSRS(expanded); err != nil {
		return err
	}
	rules, err := srs.Read(bytes.NewReader(b), true)
	if err != nil {
		return err
	}
	plain, err := rules.Upgrade()
	if err != nil {
		return err
	}
	if len(plain.Rules) == 0 {
		return errors.New("empty rule set")
	}
	for _, r := range plain.Rules {
		if err = validateDomainRule(r); err != nil {
			return err
		}
	}
	return nil
}
func validateDomainRule(r option.HeadlessRule) error {
	if r.Type == "logical" {
		if r.LogicalOptions.Mode != "and" && r.LogicalOptions.Mode != "or" {
			return errors.New("invalid logical mode")
		}
		if len(r.LogicalOptions.Rules) == 0 {
			return errors.New("empty logical rule")
		}
		for _, child := range r.LogicalOptions.Rules {
			if err := validateDomainRule(child); err != nil {
				return err
			}
		}
		return nil
	}
	d := r.DefaultOptions
	if len(d.Domain)+len(d.DomainSuffix)+len(d.DomainKeyword)+len(d.DomainRegex) == 0 {
		return errors.New("rule set must contain domain predicates")
	}
	for _, s := range d.DomainRegex {
		if _, err := regexp.Compile(s); err != nil {
			return err
		}
	}
	d.Domain = nil
	d.DomainSuffix = nil
	d.DomainKeyword = nil
	d.DomainRegex = nil
	d.DomainMatcher = nil
	d.Invert = false
	if !reflect.DeepEqual(d, option.DefaultHeadlessRule{}) {
		return errors.New("rule set contains non-domain predicates")
	}
	return nil
}
func (c *Cache) Ensure(ctx context.Context, id string, force bool) (path string, warning error, err error) {
	preset, err := Find(id)
	if err != nil {
		return "", nil, err
	}
	if err = storage.Mkdir(c.Dir); err != nil {
		return "", nil, err
	}
	lock, err := os.OpenFile(filepath.Join(c.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return "", nil, err
	}
	defer lock.Close() //nolint:errcheck
	if err = storage.Own(lock.Name()); err != nil {
		return "", nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return "", nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck
	old, oldErr := c.verified(id)
	if oldErr == nil && !force && time.Since(old.Checked) < FreshFor {
		return c.path(old), nil, nil
	}
	fresh, updateErr := c.download(ctx, preset)
	if updateErr == nil {
		return c.path(fresh), nil, nil
	}
	if oldErr == nil {
		return c.path(old), fmt.Errorf("%s update failed: %w; keeping verified copy %s", id, updateErr, old.SHA256), nil
	}
	return "", nil, fmt.Errorf("%s: update failed: %w; no verified cache (%w)", id, updateErr, oldErr)
}
func (c *Cache) download(ctx context.Context, p Preset) (Record, error) {
	r := Record{URL: c.BaseURL + p.File}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return r, err
	}
	if req.URL.Scheme != "https" {
		return r, errors.New("HTTPS required")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return r, err
	}
	if err = ValidateSRS(b); err != nil {
		return r, err
	}
	r.SHA256 = fmt.Sprintf("%x", sha256.Sum256(b))
	r.Checked = time.Now().UTC()
	if _, err = os.Stat(c.path(r)); os.IsNotExist(err) {
		err = storage.Write(c.path(r), b)
	} else if err == nil {
		existing, e := os.ReadFile(c.path(r))
		if e != nil {
			return r, e
		}
		if !bytes.Equal(existing, b) {
			return r, errors.New("immutable cache file is corrupt")
		}
	}
	if err != nil {
		return r, err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return r, err
	}
	err = storage.Write(filepath.Join(c.Dir, p.ID+".json"), data)
	return r, err
}
func (c *Cache) Prepare(ctx context.Context, p *Policy, force bool) (*Prepared, []error, error) {
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	if p == nil || !p.Enabled {
		return nil, nil, nil
	}
	result := &Prepared{Policy: p, Paths: map[string]string{}, FakeIPPath: filepath.Join(c.Dir, "fakeip.db")}
	var warnings []error
	var errs []error
	for _, preset := range Presets {
		if _, ok := p.Presets[preset.ID]; !ok {
			continue
		}
		path, w, err := c.Ensure(ctx, preset.ID, force)
		if w != nil {
			warnings = append(warnings, w)
			if force {
				errs = append(errs, w)
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
		result.Paths[preset.ID] = path
	}
	if err := storage.Mkdir(c.Dir); err != nil {
		errs = append(errs, err)
	}
	return result, warnings, errors.Join(errs...)
}

// Inspect verifies the currently published copy without refreshing it.
func (c *Cache) Inspect(id string) (Record, error) {
	if _, err := Find(id); err != nil {
		return Record{}, err
	}
	return c.verified(id)
}
