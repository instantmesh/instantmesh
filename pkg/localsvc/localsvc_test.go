package localsvc

import (
	"errors"
	"reflect"
	"testing"
)

func TestKnownServicesReturnsCopy(t *testing.T) {
	got := KnownServices()
	if len(got) != len(knownServices) {
		t.Fatalf("件数 = %d, want %d", len(got), len(knownServices))
	}
	if got[0].Port != 11434 || got[0].Label != "Ollama" {
		t.Errorf("先頭 = %+v, want Ollama/11434", got[0])
	}
	// 返り値を書き換えても内部の表は変わらないこと。
	got[0] = KnownService{Port: 1, Label: "書き換え"}
	if knownServices[0].Port != 11434 {
		t.Errorf("内部表が書き換わった: %+v", knownServices[0])
	}
}

func TestScanPorts(t *testing.T) {
	want := []int{11434, 1234, 8000, 8080, 3000, 80}
	if got := ScanPorts(); !reflect.DeepEqual(got, want) {
		t.Errorf("ScanPorts() = %v, want %v", got, want)
	}
}

func TestLabelFor(t *testing.T) {
	tests := []struct {
		port      int
		wantLabel string
		wantOK    bool
	}{
		{11434, "Ollama", true},
		{1234, "LM Studio", true},
		{8000, "vLLM", true},
		{8080, "Open WebUI", true},
		{3000, "開発サーバー", true},
		{80, "Dify", true},
		{9999, "", false},
	}
	for _, tt := range tests {
		label, ok := LabelFor(tt.port)
		if label != tt.wantLabel || ok != tt.wantOK {
			t.Errorf("LabelFor(%d) = (%q, %v), want (%q, %v)", tt.port, label, ok, tt.wantLabel, tt.wantOK)
		}
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port    int
		wantErr bool
	}{
		{MinPort, false},
		{MaxPort, false},
		{11434, false},
		{0, true},
		{-1, true},
		{65536, true},
	}
	for _, tt := range tests {
		err := ValidatePort(tt.port)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePort(%d) err = %v, wantErr %v", tt.port, err, tt.wantErr)
		}
		if err != nil && !errors.Is(err, ErrInvalidPort) {
			t.Errorf("ValidatePort(%d) = %v, want ErrInvalidPort でラップ", tt.port, err)
		}
	}
}

func TestCandidates(t *testing.T) {
	tests := []struct {
		name   string
		open   []int
		manual []int
		want   []Candidate
	}{
		{
			name: "空",
			want: []Candidate{},
		},
		{
			name: "既知ポートは表の順に並ぶ（入力順に依らない）",
			open: []int{3000, 11434, 80},
			want: []Candidate{
				{Port: 11434, Label: "Ollama", Detected: true},
				{Port: 3000, Label: "開発サーバー", Detected: true},
				{Port: 80, Label: "Dify", Detected: true},
			},
		},
		{
			name:   "未知ポートは既知の後ろに昇順で並ぶ",
			open:   []int{7000},
			manual: []int{5000, 11434, 60000},
			want: []Candidate{
				{Port: 11434, Label: "Ollama", Detected: false},
				{Port: 5000, Detected: false},
				{Port: 7000, Detected: true},
				{Port: 60000, Detected: false},
			},
		},
		{
			name:   "open と manual の重複は 1 件に畳まれ Detected=true",
			open:   []int{8000},
			manual: []int{8000},
			want: []Candidate{
				{Port: 8000, Label: "vLLM", Detected: true},
			},
		},
		{
			name:   "各引数内の重複も畳まれる",
			open:   []int{1234, 1234},
			manual: []int{4321, 4321},
			want: []Candidate{
				{Port: 1234, Label: "LM Studio", Detected: true},
				{Port: 4321, Detected: false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Candidates(tt.open, tt.manual)
			if err != nil {
				t.Fatalf("Candidates() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Candidates() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCandidatesInvalidPort(t *testing.T) {
	if _, err := Candidates([]int{0}, nil); !errors.Is(err, ErrInvalidPort) {
		t.Errorf("open に範囲外: err = %v, want ErrInvalidPort", err)
	}
	if _, err := Candidates(nil, []int{70000}); !errors.Is(err, ErrInvalidPort) {
		t.Errorf("manual に範囲外: err = %v, want ErrInvalidPort", err)
	}
}
