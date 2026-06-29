package locksmith

// checkBinaryAccess enforces binary whitelisting before accessing secrets.
// Currently this is a placeholder that always allows execution.
// Future implementation can read allowed/denied binary lists from l.Options.
func (l *Locksmith) checkBinaryAccess() error {
	// TODO: implement real binary whitelist/deny logic.
	// Example placeholder:
	// execPath, err := os.Executable()
	// if err != nil { return err }
	// if l.Options.AllowedBinaries != nil && !contains(l.Options.AllowedBinaries, execPath) {
	//     return fmt.Errorf("binary %s is not allowed by access control", execPath)
	// }
	return nil
}
