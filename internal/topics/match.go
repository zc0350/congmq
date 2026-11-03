package topics

import "strings"

// Match reports whether the topic pattern matches the given subject. The
// subject is normally a concrete topic name, but a pattern may also be tested
// against a subscription filter, which is how an ACL decides whether a client
// may ask for "#". Wildcards inside the subject are then treated as the plain
// characters they are.
func Match(pattern, subject string) bool {
	p := strings.Split(pattern, string(Separator))
	s := strings.Split(subject, string(Separator))
	if len(p) == 0 || len(s) == 0 {
		return false
	}
	// A pattern that starts with a wildcard never reaches a $-prefixed
	// subject, which is how $SYS stays out of "#".
	if s[0] != "" && s[0][0] == systemPrefix[0] && (p[0] == singleLevel || p[0] == multiLevel) {
		return false
	}
	return matchLevels(p, s, 0, 0)
}

func matchLevels(pattern, subject []string, pi, si int) bool {
	if pi == len(pattern) {
		return si == len(subject)
	}
	if pattern[pi] == multiLevel {
		// '#' covers this level and everything below it, including the case
		// where the subject stops here: "a/#" matches "a".
		return true
	}
	if si == len(subject) {
		return false
	}
	if pattern[pi] == singleLevel || pattern[pi] == subject[si] {
		return matchLevels(pattern, subject, pi+1, si+1)
	}
	return false
}
