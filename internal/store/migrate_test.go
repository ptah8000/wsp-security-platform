package store

import (
	"testing"
	"testing/fstest"
)

func TestListUpMigrations(t *testing.T) {
	fsys := fstest.MapFS{
		"001_init.up.sql":   {Data: []byte("-- up")},
		"001_init.down.sql": {Data: []byte("-- down")},
		"002_extra.up.sql":  {Data: []byte("-- up2")},
		"readme.txt":        {Data: []byte("ignore")},
		"003_bad.up":        {Data: []byte("ignore")},
	}

	got, err := listUpMigrations(fsys)
	if err != nil {
		t.Fatalf("listUpMigrations: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if got[0].version != "001" || got[0].name != "init" {
		t.Errorf("first = %+v, want version=001 name=init", got[0])
	}
	if got[1].version != "002" || got[1].name != "extra" {
		t.Errorf("second = %+v, want version=002 name=extra", got[1])
	}
}

func TestListUpMigrationsEmpty(t *testing.T) {
	got, err := listUpMigrations(fstest.MapFS{})
	if err != nil {
		t.Fatalf("listUpMigrations: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}
