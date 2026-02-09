package accesslog

// Exports for testing

func (l *Logger) IsManagedPath(path string) bool {
	return l.isManagedPath(path)
}
