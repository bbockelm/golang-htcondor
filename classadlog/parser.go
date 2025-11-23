package classadlog

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Parser reads and parses the job queue log file
type Parser struct {
	filename   string
	file       *os.File
	scanner    *bufio.Scanner
	nextOffset int64
	lastEntry  *LogEntry
}

// NewParser creates a new log parser
func NewParser(filename string) *Parser {
	return &Parser{
		filename: filename,
	}
}

// Open opens the log file
func (p *Parser) Open() error {
	if p.file != nil {
		return fmt.Errorf("file already open")
	}

	f, err := os.Open(p.filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	p.file = f
	p.scanner = bufio.NewScanner(f)

	// If we have a saved offset, seek to it
	if p.nextOffset > 0 {
		if _, err := f.Seek(p.nextOffset, io.SeekStart); err != nil {
			_ = p.file.Close()
			p.file = nil
			return fmt.Errorf("failed to seek to offset %d: %w", p.nextOffset, err)
		}
	}

	return nil
}

// Close closes the log file
func (p *Parser) Close() error {
	if p.file == nil {
		return nil
	}

	// Save current offset before closing
	if offset, err := p.file.Seek(0, io.SeekCurrent); err == nil {
		p.nextOffset = offset
	}

	err := p.file.Close()
	p.file = nil
	p.scanner = nil
	return err
}

// ReadEntry reads the next log entry from the file
// Returns io.EOF when end of file is reached
func (p *Parser) ReadEntry() (*LogEntry, error) {
	if p.file == nil {
		return nil, fmt.Errorf("file not open")
	}

	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}

	line := strings.TrimSpace(p.scanner.Text())

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return p.ReadEntry() // Recursive call to get next non-empty line
	}

	entry, err := p.parseLine(line)
	if err != nil {
		return nil, fmt.Errorf("failed to parse line %q: %w", line, err)
	}

	p.lastEntry = entry
	return entry, nil
}

// parseLine parses a single line into a LogEntry
// HTCondor job_queue.log uses numeric operation codes:
//
//	1 = New classad
//	2 = Destroy classad
//	3 = Set attribute
//	4 = Delete attribute
//	5 = Begin transaction
//	6 = End transaction
//	7 = Log historical sequence number
//
// Real HTCondor logs use codes 101-107 (base + 100)
//
// Format: <opcode> <key> [<name> [<value>]]
func (p *Parser) parseLine(line string) (*LogEntry, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty line")
	}

	entry := &LogEntry{}

	// Check if first field is a number (numeric format)
	opcode := parts[0]

	// Handle opcodes 101-107 by normalizing to 1-7
	if len(opcode) == 3 && opcode[0] == '1' && opcode[1] == '0' {
		// 101-107 -> 1-7
		opcode = string(opcode[2])
	}

	switch opcode {
	case "1", "NewClassAd":
		// Format: 1 <key> <mytype> <targettype>
		if len(parts) < 2 {
			return nil, fmt.Errorf("NewClassAd requires at least key")
		}
		entry.OpType = OpNewClassAd
		entry.Key = parts[1]
		if len(parts) >= 3 {
			entry.MyType = parts[2]
		}
		if len(parts) >= 4 {
			entry.TargetType = parts[3]
		}

	case "2", "DestroyClassAd":
		// Format: 2 <key>
		if len(parts) < 2 {
			return nil, fmt.Errorf("DestroyClassAd requires key")
		}
		entry.OpType = OpDestroyClassAd
		entry.Key = parts[1]

	case "3", "SetAttribute":
		// Format: 3 <key> <name> <value>
		if len(parts) < 4 {
			return nil, fmt.Errorf("SetAttribute requires key, name, and value")
		}
		entry.OpType = OpSetAttribute
		entry.Key = parts[1]
		entry.Name = parts[2]
		// Value is everything from the 4th field onward
		entry.Value = strings.Join(parts[3:], " ")

	case "4", "DeleteAttribute":
		// Format: 4 <key> <name>
		if len(parts) < 3 {
			return nil, fmt.Errorf("DeleteAttribute requires key and name")
		}
		entry.OpType = OpDeleteAttribute
		entry.Key = parts[1]
		entry.Name = parts[2]

	case "5", "BeginTransaction":
		entry.OpType = OpBeginTransaction

	case "6", "EndTransaction":
		entry.OpType = OpEndTransaction

	case "7", "LogHistoricalSequenceNumber":
		entry.OpType = OpLogHistoricalSequenceNumber

	default:
		// Unknown operation - skip it rather than failing
		// HTCondor may use other operation codes we don't need to parse
		entry.OpType = OpBeginTransaction // Treat as no-op
	}

	return entry, nil
}

// SetNextOffset sets the file offset for the next read
func (p *Parser) SetNextOffset(offset int64) {
	p.nextOffset = offset
}

// GetNextOffset returns the current file offset
func (p *Parser) GetNextOffset() int64 {
	return p.nextOffset
}

// GetLastEntry returns the last entry read
func (p *Parser) GetLastEntry() *LogEntry {
	return p.lastEntry
}

// GetFilename returns the log filename
func (p *Parser) GetFilename() string {
	return p.filename
}
