package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"
)

// This is required; without it onet/log/testuitl.go:interestingGoroutines will
// call main.main() interesting.
func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestCli(t *testing.T) {
	dir, err := ioutil.TempDir("", "bc-test")
	if err != nil {
		t.Fatal(err)
	}
	getDataPath = func(in string) string {
		return dir
	}
	defer os.RemoveAll(dir)

	l := onet.NewTCPTest(cothority.Suite)
	_, roster, _ := l.GenTree(3, true)

	defer l.CloseAll()

	// All this mess is to take the roster we have from onet.NewTCPTest
	// and get it into a file that create can read.
	g := &app.Group{Roster: roster}
	rf := path.Join(dir, "roster.toml")
	err = g.Save(cothority.Suite, rf)
	require.NoError(t, err)

	interval := 100 * time.Millisecond

	log.Lvl1("create: ")
	b := &bytes.Buffer{}
	cliApp.Writer = b
	cliApp.ErrWriter = b
	args := []string{"bcadmin", "create", "-roster", rf, "--interval", interval.String()}
	err = cliApp.Run(args)
	require.NoError(t, err)
	require.Contains(t, string(b.Bytes()), "Created")

	// Collect the BC config filename that create() left for us,
	// and make it available for the next tests.
	bc := cliApp.Metadata["BC"]
	require.IsType(t, "", bc)
	os.Setenv("BC", bc.(string))

	log.Lvl1("latest: ")
	b = &bytes.Buffer{}
	cliApp.Writer = b
	cliApp.ErrWriter = b
	args = []string{"bcadmin", "latest"}
	err = cliApp.Run(args)
	require.NoError(t, err)
	require.Contains(t, string(b.Bytes()), "Index: 0")
	require.Contains(t, string(b.Bytes()), "Roster: tcp://127.0.0.1")

	log.Lvl1("darc show: ")
	b = &bytes.Buffer{}
	cliApp.Writer = b
	cliApp.ErrWriter = b
	args = []string{"bcadmin", "darc", "show"}
	err = cliApp.Run(args)
	require.NoError(t, err)
	require.Contains(t, string(b.Bytes()), "Ver:\t0")

	log.Lvl1("darc rule: ")
	b = &bytes.Buffer{}
	cliApp.Writer = b
	cliApp.ErrWriter = b
	args = []string{"bcadmin", "darc", "rule", "-identity", "foo", "-rule", "spawn:xxx"}
	err = cliApp.Run(args)
	require.NoError(t, err)
	require.Equal(t, string(b.Bytes()), "")

	log.Lvl1("darc show: ")
	b = &bytes.Buffer{}
	cliApp.Writer = b
	cliApp.ErrWriter = b
	args = []string{"bcadmin", "darc", "show"}
	err = cliApp.Run(args)
	require.NoError(t, err)
	require.Contains(t, string(b.Bytes()), "Ver:\t1")
	require.Contains(t, string(b.Bytes()), "spawn:xxx")

}
