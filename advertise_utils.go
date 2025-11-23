package htcondor

import (
	"strings"

	"github.com/bbockelm/cedar/commands"
)

// ParseAdvertiseCommand parses an UPDATE command string to CommandType
// This is a shared utility used by both HTTP handlers and MCP handlers
func ParseAdvertiseCommand(cmd string) (commands.CommandType, bool) {
	// Map command strings to command types
	cmdMap := map[string]commands.CommandType{
		"UPDATE_STARTD_AD":          commands.UPDATE_STARTD_AD,
		"UPDATE_SCHEDD_AD":          commands.UPDATE_SCHEDD_AD,
		"UPDATE_MASTER_AD":          commands.UPDATE_MASTER_AD,
		"UPDATE_SUBMITTOR_AD":       commands.UPDATE_SUBMITTOR_AD,
		"UPDATE_COLLECTOR_AD":       commands.UPDATE_COLLECTOR_AD,
		"UPDATE_NEGOTIATOR_AD":      commands.UPDATE_NEGOTIATOR_AD,
		"UPDATE_LICENSE_AD":         commands.UPDATE_LICENSE_AD,
		"UPDATE_STORAGE_AD":         commands.UPDATE_STORAGE_AD,
		"UPDATE_ACCOUNTING_AD":      commands.UPDATE_ACCOUNTING_AD,
		"UPDATE_GRID_AD":            commands.UPDATE_GRID_AD,
		"UPDATE_HAD_AD":             commands.UPDATE_HAD_AD,
		"UPDATE_AD_GENERIC":         commands.UPDATE_AD_GENERIC,
		"UPDATE_STARTD_AD_WITH_ACK": commands.UPDATE_STARTD_AD_WITH_ACK,
	}

	cmdType, ok := cmdMap[strings.ToUpper(cmd)]
	return cmdType, ok
}
