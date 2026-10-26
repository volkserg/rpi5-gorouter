package config

import (
	"os"
	"strings"
	"testing"
)

// Демон пишет списки из веб-интерфейса в DefaultDir, а юнит routerd —
// ProtectSystem=strict: каталог должен быть в ReadWritePaths (на стенде это
// не проверить — OrbStack отключает такую изоляцию).
func TestUnitAllowsConfigDirWrites(t *testing.T) {
	data, err := os.ReadFile("../../deploy/systemd/routerd.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		paths, ok := strings.CutPrefix(strings.TrimSpace(line), "ReadWritePaths=")
		if !ok {
			continue
		}
		for _, p := range strings.Fields(paths) {
			if strings.TrimPrefix(p, "-") == DefaultDir {
				return
			}
		}
	}
	t.Fatalf("routerd.service: %s нет в ReadWritePaths", DefaultDir)
}
