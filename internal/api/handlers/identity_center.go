package handlers

import (
	"net/http"

	"github.com/Zero0x00/cloudrift/internal/identitycenter"
)

// GetIdentityCenter returns the IAM Identity Center view for a scan: permission sets, assignments and who reaches which account.
func GetIdentityCenter(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, identitycenter.Build(scanID, assets, rels))
	}
}
