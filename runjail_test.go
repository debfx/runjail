package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"

	"github.com/otiai10/copy"
)

func runTest(testName string, args []string) (string, error) {
	env := os.Environ()
	env = append(env, "RUNJAIL_TEST_INNER=1")

	cmdArgs := append([]string{"/proc/self/exe"}, args...)
	cmdArgs = append(cmdArgs, "--ro", "testdata/scripts/"+testName, "--", "testdata/scripts/"+testName)

	cmd := exec.Cmd{
		Path:   "/proc/self/exe",
		Args:   cmdArgs,
		Stderr: os.Stderr,
		Env:    env,
	}
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n"), err
}

func TestMain(m *testing.M) {
	// inside a test, run the main binary (not the test)
	if os.Getenv("RUNJAIL_TEST_INNER") == "1" {
		main()
		return
	}

	// start test runner
	os.Exit(m.Run())
}

func assertNil(t *testing.T, obj interface{}) {
	if obj != nil {
		t.Fatal(obj)
	}
}

func assertEqual(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Fatal(fmt.Printf("Expected '%s', got '%s'", expected, actual))
	}
}

func createTempDataDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", t.Name())
	if err != nil {
		t.Errorf("TempDir create failed: %v", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("TempDir cleanup failed: %v", err)
		}
	})

	err = copy.Copy("testdata", tempDir)
	if err != nil {
		t.Errorf("copy test data failed: %v", err)
	}

	return tempDir
}

func TestCwd(t *testing.T) {
	stdout, err := runTest("cwd", []string{"--cwd", "/tmp"})
	assertNil(t, err)
	assertEqual(t, "/tmp", stdout)
}

func TestCwdDefault(t *testing.T) {
	cwd, err := os.Getwd()
	assertNil(t, err)

	stdout, err := runTest("cwd", []string{})
	assertNil(t, err)
	assertEqual(t, cwd, stdout)
}

func TestRo(t *testing.T) {
	tempDir := createTempDataDir(t)

	stdout, err := runTest("ro", []string{"--cwd", tempDir, "--ro", path.Join(tempDir, "data/ro")})
	assertNil(t, err)
	assertEqual(t, "rotest", stdout)
}

func TestBindRo(t *testing.T) {
	tempDir := createTempDataDir(t)

	stdout, err := runTest("bindro", []string{"--bind-ro", path.Join(tempDir, "data/ro") + ":/bindro"})
	assertNil(t, err)
	assertEqual(t, "rotest", stdout)
}

func TestUnshare(t *testing.T) {
	tempDir := createTempDataDir(t)

	stdout, err := runTest("unshare", []string{"--cwd", tempDir, "--ro", tempDir, "--seccomp", "no"})
	assertNil(t, err)
	assertEqual(t, "unsharetest", stdout)
}
