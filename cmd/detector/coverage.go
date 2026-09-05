package main

import "fmt"

type Coverage struct {
	CollectionComplete     bool     `json:"collection_complete"`
	ContentComplete        bool     `json:"content_complete"`
	AnalysisComplete       bool     `json:"analysis_complete"`
	AnalysisTruncatedFiles []string `json:"analysis_truncated_files,omitempty"`
}

func fullCoverage() Coverage {
	return Coverage{CollectionComplete: true, ContentComplete: true, AnalysisComplete: true}
}

// Report limits using exactly the statement splitter used by the behavior layer.
func recordAnalysisCoverage(blobs []FileBlob, status *ScanStatus) {
	seen := map[string]bool{}
	for _, b := range blobs {
		if seen[b.Rel] {
			continue
		}
		seen[b.Rel] = true
		if b.Lower == "" || !(b.IsCode || isPackagePath(b.Rel) || isKnownTextConfigPath(b.Rel)) || (b.IsDoc && !isPackagePath(b.Rel)) {
			continue
		}
		statements := splitLogicalStatements(b.Lower)
		truncated := len(statements) > 12000
		for _, st := range statements {
			if len(st.Text) > 32768 {
				truncated = true
				break
			}
		}
		if truncated {
			status.Coverage.AnalysisComplete = false
			if len(status.Coverage.AnalysisTruncatedFiles) < maxScanErrorSamples {
				status.Coverage.AnalysisTruncatedFiles = append(status.Coverage.AnalysisTruncatedFiles, b.Rel)
			}
			status.markIncomplete("behavior analysis statement count or length limit reached")
		}
	}
}

func coverageReason(status ScanStatus) string {
	return fmt.Sprintf("collection=%t content=%t analysis=%t", status.Coverage.CollectionComplete, status.Coverage.ContentComplete, status.Coverage.AnalysisComplete)
}
