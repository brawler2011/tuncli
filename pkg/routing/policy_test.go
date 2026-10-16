package routing

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/storage"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, srs.Write(&b, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"ru", "gemini.google.com"}}}}}, 3))
	return b.Bytes()
}
func TestNormalize(t *testing.T) {
	for input, want := range map[string]string{"MY.ITMO.RU.": "my.itmo.ru", "ПРИМЕР.РФ": "xn--e1afmkfd.xn--p1ai", "example.com": "example.com"} {
		got, err := Normalize(input)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, s := range []string{"https://example.com", "1.2.3.4", "::1", "*.ru", "foo..ru", "-foo.ru", "foo-.ru", "foo_bar.ru", " foo.ru", "foo.ru/path", ""} {
		_, err := Normalize(s)
		assert.Error(t, err, s)
	}
}
func TestPolicyOrdering(t *testing.T) {
	p := New()
	p.Presets = map[string]Outbound{"ru": Direct, "ai": VPN}
	p.Rules = []Rule{{"ru", true, Direct}, {"itmo.ru", true, VPN}, {"my.itmo.ru", false, Direct}, {"itmo.ru", false, VPN}}
	require.NoError(t, p.Validate())
	entries := (&Prepared{Policy: p}).Entries()
	require.Len(t, entries, 6)
	assert.Equal(t, map[string]any{"domain": []string{"my.itmo.ru"}}, entries[0].Match)
	assert.Equal(t, map[string]any{"domain_suffix": []string{"itmo.ru"}}, entries[2].Match)
	assert.Equal(t, VPN, entries[4].Outbound)
	assert.Equal(t, Direct, entries[5].Outbound)
	other := New()
	other.Presets = map[string]Outbound{"ai": VPN, "ru": Direct}
	other.Rules = append([]Rule(nil), p.Rules...)
	assert.Equal(t, entries, (&Prepared{Policy: other}).Entries())
	p.Presets["unknown"] = VPN
	assert.ErrorContains(t, p.Validate(), "unknown routing preset")
}
func TestCache(t *testing.T) {
	data := fixture(t)
	require.NoError(t, ValidateSRS(data))
	var hits atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "no", 500)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	cache := NewCache(t.TempDir())
	cache.BaseURL = server.URL + "/"
	cache.Client = server.Client()
	path, w, err := cache.Ensure(context.Background(), "ru", false)
	require.NoError(t, err)
	require.NoError(t, w)
	assert.FileExists(t, path)
	_, _, err = cache.Ensure(context.Background(), "ru", false)
	require.NoError(t, err)
	assert.EqualValues(t, 1, hits.Load())
	r, err := cache.Status("ru")
	require.NoError(t, err)
	r.Checked = time.Now().Add(-25 * time.Hour)
	b, err := json.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, storage.Write(filepath.Join(cache.Dir, "ru.json"), b))
	fail.Store(true)
	fallback, w, err := cache.Ensure(context.Background(), "ru", false)
	require.NoError(t, err)
	require.ErrorContains(t, w, "keeping verified copy")
	assert.Equal(t, path, fallback)
	_, _, err = cache.Ensure(context.Background(), "ai", false)
	require.ErrorContains(t, err, "no verified cache")
	p := New()
	p.Enabled = true
	p.Presets["ru"] = Direct
	_, _, err = cache.Prepare(context.Background(), p, true)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte("corrupt"), 0644))
	_, _, err = cache.Ensure(context.Background(), "ru", false)
	assert.Error(t, err)
}
func TestCacheConcurrent(t *testing.T) {
	data := fixture(t)
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write(data) }))
	defer server.Close()
	cache := NewCache(t.TempDir())
	cache.BaseURL = server.URL + "/"
	cache.Client = server.Client()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() { _, _, err := cache.Ensure(context.Background(), "ru", false); assert.NoError(t, err) })
	}
	wg.Wait()
	assert.EqualValues(t, 1, hits.Load())
}
func TestCacheBadDownloads(t *testing.T) {
	for _, kind := range []string{"invalid", "incompatible", "timeout", "oversized", "non-domain"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "invalid":
					_, _ = w.Write([]byte("bad"))
				case "incompatible":
					b := fixture(t)
					b[3] = 255
					_, _ = w.Write(b)
				case "timeout":
					<-r.Context().Done()
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte{0}, MaxSize+1))
				case "non-domain":
					var b bytes.Buffer
					assert.NoError(t, srs.Write(&b, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{IPCIDR: []string{"1.2.3.0/24"}}}}}, 3))
					_, _ = w.Write(b.Bytes())
				}
			}))
			defer server.Close()
			cache := NewCache(t.TempDir())
			cache.BaseURL = server.URL + "/"
			cache.Client = server.Client()
			cache.Client.Timeout = 50 * time.Millisecond
			_, _, err := cache.Ensure(context.Background(), "ru", true)
			require.Error(t, err)
			_, err = cache.Status("ru")
			assert.Error(t, err)
		})
	}
}

func TestMalformedSRSLengths(t *testing.T) {
	for _, expanded := range [][]byte{{0, 1}, {0xff, 0xff, 0xff, 0xff, 0x7f}} {
		var b bytes.Buffer
		b.Write([]byte{'S', 'R', 'S', 3})
		z := zlib.NewWriter(&b)
		_, err := z.Write(expanded)
		require.NoError(t, err)
		require.NoError(t, z.Close())
		require.Error(t, ValidateSRS(b.Bytes()))
	}
	var expanded bytes.Buffer
	var number [10]byte
	n := binary.PutUvarint(number[:], 1)
	expanded.Write(number[:n])
	expanded.Write([]byte{0, 2, 0})
	n = binary.PutUvarint(number[:], 1<<40)
	expanded.Write(number[:n])
	assert.Error(t, guardSRS(expanded.Bytes()))
}
