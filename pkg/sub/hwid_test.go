package sub

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceHWIDWithoutHome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing bool
	}{
		{name: "existing", existing: true},
		{name: "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", "")
			previousDir, previousPrivate := config.Directory, storage.Private
			config.Directory, storage.Private = t.TempDir(), true
			t.Cleanup(func() { config.Directory, storage.Private = previousDir, previousPrivate })
			path := filepath.Join(config.Directory, "hwid")
			known := "00000000-0000-4000-8000-000000000001"
			if tc.existing {
				require.NoError(t, os.WriteFile(path, []byte(known+"\n"), 0600))
			}
			id, err := LoadOrCreateHWID()
			require.NoError(t, err)
			_, err = uuid.Parse(id)
			require.NoError(t, err)
			if tc.existing {
				require.Equal(t, known, id)
			}
			again, err := LoadOrCreateHWID()
			require.NoError(t, err)
			require.Equal(t, id, again)
			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0600), info.Mode().Perm())
		})
	}
}

func TestServiceFetchSendsHWIDWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	previousDir, previousPrivate := config.Directory, storage.Private
	config.Directory, storage.Private = t.TempDir(), true
	t.Cleanup(func() { config.Directory, storage.Private = previousDir, previousPrivate })
	known := "00000000-0000-4000-8000-000000000001"
	require.NoError(t, os.WriteFile(filepath.Join(config.Directory, "hwid"), []byte(known), 0600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, known, r.Header.Get("X-HWID"))
		_, _ = fmt.Fprint(w, "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443#Test")
	}))
	t.Cleanup(server.Close)
	nodes, err := FetchAndParse(server.URL)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "192.0.2.1", nodes[0].Server)
}

func TestFetchFailsWhenHWIDCannotBeLoaded(t *testing.T) {
	previousDir := config.Directory
	config.Directory = filepath.Join(t.TempDir(), "not-a-directory")
	t.Cleanup(func() { config.Directory = previousDir })
	require.NoError(t, os.WriteFile(config.Directory, nil, 0600))
	// Fail before any HTTP request when local device state is unavailable.
	_, err := FetchAndParse("https://example.invalid/subscription")
	require.ErrorContains(t, err, "loading device identifier failed")
}
