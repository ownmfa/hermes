package hlog

func init() {
	SetDefault(NewConsole("DEBUG"))
}
