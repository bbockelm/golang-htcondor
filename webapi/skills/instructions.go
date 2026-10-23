package skills

import (
	"fmt"
	"strings"
)

// maxListed bounds the catalogue a prompt carries. A site with more skills
// than this has more than any model will weigh in one reading; the rest
// stay reachable through the listing tool.
const maxListed = 60

// Instructions is the section a surface adds to its prompt when the
// deployment publishes skills.
//
// It names them inline rather than only pointing at a tool. A model reads
// its instructions before deciding anything, so the catalogue is what makes
// it recognise that a task is covered here; "call the skills tool" is
// advice it has no reason to take until after it has already guessed, which
// is one guess too late.
//
// howToRead is the one part that differs between surfaces, because it names
// an affordance only that surface has -- an MCP tool and resource URI on one
// side, a chat tool on the other. Everything else is shared on purpose: the
// catalogue and the instruction to consult it before acting are what the
// site is actually publishing, and an agent that reaches this server one way
// should not be told something different from one that reaches it the other.
//
// Empty when the library is empty, so a caller can concatenate it
// unconditionally.
func (l *Library) Instructions(howToRead string) string {
	if l.Len() == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## Site skills\n\n")
	fmt.Fprintf(&b, "This access point publishes %d site-authored skill(s): its own "+
		"documentation for how work is done here -- local conventions, queue policy, "+
		"which resources to request, worked procedures.\n\n", l.Len())
	b.WriteString("**Consult the relevant skill before using other tools** when a task " +
		"touches any of the subjects below. They describe choices specific to this site " +
		"that general HTCondor knowledge will contradict or omit. ")
	b.WriteString(strings.TrimSpace(howToRead))
	b.WriteString("\n\n")

	listed := l.List()
	truncated := false
	if len(listed) > maxListed {
		listed, truncated = listed[:maxListed], true
	}
	for _, sk := range listed {
		if d := strings.TrimSpace(sk.Description); d != "" {
			fmt.Fprintf(&b, "- `%s` -- %s: %s\n", sk.ID, sk.Name, d)
		} else {
			fmt.Fprintf(&b, "- `%s` -- %s\n", sk.ID, sk.Name)
		}
	}
	if truncated {
		fmt.Fprintf(&b, "\n(%d more not listed here.)\n", l.Len()-maxListed)
	}
	return b.String()
}
