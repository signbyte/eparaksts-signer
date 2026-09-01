package signing

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestHashFilesForCoSign proves a container co-sign registers ALL inner data
// objects under one signature, normalizing each algorithm label to SignAPI's bare
// "SHA256" — so the co-signature targets exactly the files the container holds.
func TestHashFilesForCoSign(t *testing.T) {
	d := InputDocument{
		FileName: "bundle.edoc",
		Files: []InputFile{
			{Name: "a.pdf", Digest: "hA", DigestAlgorithm: "SHA-256"},
			{Name: "b.txt", Digest: "hB", DigestAlgorithm: "sha256"},
		},
	}

	files := hashFilesFor(d)
	qt.Assert(t, qt.Equals(len(files), 2))
	qt.Check(t, qt.Equals(files[0].Name, "a.pdf"))
	qt.Check(t, qt.Equals(files[0].Digest, "hA"))
	qt.Check(t, qt.Equals(files[0].DigestAlgorithm, "SHA256")) // hyphen stripped
	qt.Check(t, qt.Equals(files[1].Name, "b.txt"))
	qt.Check(t, qt.Equals(files[1].DigestAlgorithm, "SHA256"))
}

// TestHashFilesForSingle proves a normal hash-only document registers its single
// digest under the document filename (the unchanged, dominant path).
func TestHashFilesForSingle(t *testing.T) {
	d := InputDocument{FileName: "contract.pdf", Hash: "h", DigestAlgorithm: "SHA-256"}

	files := hashFilesFor(d)
	qt.Assert(t, qt.Equals(len(files), 1))
	qt.Check(t, qt.Equals(files[0].Name, "contract.pdf"))
	qt.Check(t, qt.Equals(files[0].Digest, "h"))
	qt.Check(t, qt.Equals(files[0].DigestAlgorithm, "SHA256"))
}
