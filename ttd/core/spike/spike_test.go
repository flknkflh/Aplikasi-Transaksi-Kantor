package spike_test

import (
	"testing"

	"example.internal/pqc-pdf-sign/core/spike"
	"example.internal/pqc-pdf-sign/core/testpdf"
)

// TestRun_SinglePage is the automated form of the M1 acceptance run
// (Rencana V1 §25.3, §25.4, §25.5): sign locally, verify against the explicit
// Root CA, and confirm a tampered PDF and a wrong Root CA are both rejected.
func TestRun_SinglePage(t *testing.T) {
	rep, err := spike.Run(spike.Config{
		InputPDF:    testpdf.Sample(),
		SignerName:  "Spike Windows",
		DeviceLabel: "Windows Laptop",
		Platform:    "windows",
	})
	if err != nil {
		t.Fatalf("spike.Run: %v", err)
	}
	for _, c := range rep.Checks {
		t.Logf("check %-32s passed=%v  %s", c.Name, c.Passed, c.Detail)
		if !c.Passed {
			t.Errorf("check %q failed: %s", c.Name, c.Detail)
		}
	}
	if !rep.Passed {
		t.Fatalf("spike report did not pass")
	}
	if rep.SignedSHA512 == rep.OriginalSHA512 {
		t.Errorf("signed and original SHA-512 must differ")
	}
	if rep.SignatureOverhead <= 0 {
		t.Errorf("signature overhead = %d, want > 0", rep.SignatureOverhead)
	}
	t.Logf("keygen=%dms sign=%dms verify=%dms signedBytes=%d overhead=%d heap=%dKiB",
		rep.KeygenMillis, rep.SignMillis, rep.VerifyMillis, rep.SignedPDFBytes,
		rep.SignatureOverhead, rep.PeakHeapAllocBytes/1024)
}

func TestRun_MultiPage(t *testing.T) {
	rep, err := spike.Run(spike.Config{
		InputPDF:   testpdf.SampleMultipage(),
		SignerName: "Spike Android",
		Platform:   "android",
	})
	if err != nil {
		t.Fatalf("spike.Run (multipage): %v", err)
	}
	if !rep.Passed {
		for _, c := range rep.Checks {
			if !c.Passed {
				t.Errorf("check %q failed: %s", c.Name, c.Detail)
			}
		}
	}
}
