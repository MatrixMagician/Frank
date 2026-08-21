package cli

type Code int

const (
	CodeAcceptance   Code = 0
	CodeRejection    Code = 1
	CodeIncomplete   Code = 2
	CodeUsage        Code = 3
	CodeInconclusive Code = 4
)

func (c Code) String() string {
	switch c {
	case CodeAcceptance:
		return "acceptance"
	case CodeRejection:
		return "rejection"
	case CodeIncomplete:
		return "incomplete"
	case CodeUsage:
		return "usage"
	case CodeInconclusive:
		return "inconclusive"
	default:
		return "unknown"
	}
}
