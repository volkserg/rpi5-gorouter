package api

import "testing"

func TestParseJournal(t *testing.T) {
	out := []byte(`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1792695481184698","PRIORITY":"6","MESSAGE":"level=INFO msg=\"routerd запущен\"","_PID":"1"}
не JSON
{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1792695482000000","PRIORITY":"4","MESSAGE":[108,101,118,101,108,61,87,65,82,78,27,91]}
{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1792695483000000","MESSAGE":null}
`)
	j := ParseJournal("routerd.service", "c0", out)
	if j.Cursor != "c3" || len(j.Entries) != 3 {
		t.Fatalf("журнал: %+v", j)
	}
	if e := j.Entries[0]; e.Message != `level=INFO msg="routerd запущен"` || e.Priority != 6 || e.Time != 1792695481184 {
		t.Errorf("строка: %+v", e)
	}
	if e := j.Entries[1]; e.Message != "level=WARN\x1b[" || e.Priority != 4 {
		t.Errorf("массив байтов: %+v", e)
	}
	if e := j.Entries[2]; e.Message != "" || e.Priority != 6 {
		t.Errorf("null: %+v", e)
	}
	if j := ParseJournal("u", "c0", nil); j.Cursor != "c0" || len(j.Entries) != 0 {
		t.Errorf("пустой вывод: %+v", j)
	}
}
