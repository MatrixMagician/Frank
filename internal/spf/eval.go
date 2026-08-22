package spf

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

// LookupLimit is RFC 7208 §4.6.4's cap of ten mechanisms and modifiers that
// each require a DNS query: include, a, mx, ptr, exists, and redirect.
// ip4, ip6 and all cost nothing.
const LookupLimit = 10

// SecondaryLookupLimit is RFC 7208 §4.6.4's cap on the number of MX or PTR
// hosts a single mx/ptr mechanism may resolve against; hosts beyond it are
// ignored rather than making the record a permerror.
const SecondaryLookupLimit = 10

// mechanismSpec is one row of the mechanism table: how to evaluate a parsed
// Mechanism of this Kind against an evaluation. docs/architecture.md
// requires a table rather than a switch chain so the lookup-limit
// accounting and the RFC's per-mechanism behaviour both live in one place
// per mechanism, and adding a mechanism means adding a row.
type mechanismSpec struct {
	costsLookup bool
	match       func(ctx context.Context, e *evaluator, domain string, term Mechanism, clientIP netip.Addr) (matched bool, err error)
}

var mechanismTable map[MechanismKind]mechanismSpec

func init() {
	mechanismTable = map[MechanismKind]mechanismSpec{
		MechAll:     {costsLookup: false, match: matchAll},
		MechIP4:     {costsLookup: false, match: matchIP4},
		MechIP6:     {costsLookup: false, match: matchIP6},
		MechA:       {costsLookup: true, match: matchA},
		MechMX:      {costsLookup: true, match: matchMX},
		MechPTR:     {costsLookup: true, match: matchPTR},
		MechExists:  {costsLookup: true, match: matchExists},
		MechInclude: {costsLookup: true, match: nil},
	}
}

// evaluator holds the state threaded through one Evaluate call: the
// resolver, the client IP under test (nil when NotEvaluated), the subject
// used for macro expansion, the tree being built, the lookup counter, and
// findings gathered along the way.
type evaluator struct {
	resolver       resolve.Resolver
	clientIP       *CandidateSendingIP
	subject        string
	envelopeSender string
	helo           string
	tree           *EvaluationTree
	lookups        int
	findings       []Finding
	visited        map[string]bool
}

// Evaluate parses and evaluates the SPF record for req's subject domain
// (the Envelope Sender's domain, or the HELO Identity's domain when the
// Envelope Sender is null, per RFC 7208 §2.4) against req.ClientIP,
// expanding include and redirect and enforcing the Lookup Limit, and
// returns a Result whose Tree is always populated even when req.ClientIP is
// nil and the Verdict is NotEvaluated.
func Evaluate(ctx context.Context, r resolve.Resolver, req Request) (*Result, error) {
	subject, subjectFrom := subjectDomain(req)

	e := &evaluator{
		resolver:       r,
		clientIP:       req.ClientIP,
		subject:        subject,
		envelopeSender: req.EnvelopeSender,
		helo:           req.HeloIdentity,
		tree:           &EvaluationTree{Subject: subject},
		visited:        make(map[string]bool),
	}

	var clientAddr netip.Addr
	if req.ClientIP != nil {
		clientAddr = req.ClientIP.Addr()
	}

	verdict, matched, err := e.evaluateDomain(ctx, subject, 0, clientAddr)
	if err != nil {
		return nil, err
	}

	if req.ClientIP == nil {
		verdict = NotEvaluated
	}

	result := &Result{
		Verdict:     verdict,
		Subject:     subject,
		SubjectFrom: subjectFrom,
		Matched:     matched,
		Tree:        e.tree,
		Findings:    e.findings,
		Lookups:     e.lookups,
		ClientIP:    req.ClientIP,
	}
	return result, nil
}

// subjectDomain picks SPF's subject per RFC 7208 §2.4: the Envelope
// Sender's domain, or the HELO Identity's domain when the Envelope Sender
// is null. A Verdict must always name which one it used.
func subjectDomain(req Request) (domain, from string) {
	if req.EnvelopeSender != "" {
		if _, d, ok := strings.Cut(req.EnvelopeSender, "@"); ok && d != "" {
			return d, "envelope-sender"
		}
		return req.EnvelopeSender, "envelope-sender"
	}
	return req.HeloIdentity, "helo-identity"
}

// evaluateDomain evaluates the SPF record at domain and returns the
// resulting Verdict and its Matched node. depth is used only to record on
// each Node; the lookup limit is a flat counter shared across the whole
// evaluation, not a per-depth budget, per RFC 7208 §4.6.4. visited tracks
// only the current include/redirect path (pushed on entry, popped on
// return), not every domain ever seen: two independent include branches are
// free to name the same domain, and only a domain recurring on its own
// path is an actual cycle.
func (e *evaluator) evaluateDomain(ctx context.Context, domain string, depth int, clientIP netip.Addr) (Verdict, *Node, error) {
	key := strings.ToLower(domain)
	if e.visited[key] {
		return PermError, nil, nil
	}
	e.visited[key] = true
	defer delete(e.visited, key)

	terms, verdict, done := e.fetchRecord(ctx, domain, depth)
	if done {
		return verdict, nil, nil
	}

	var redirect *Mechanism
	for _, term := range terms {
		if !term.IsMechanism {
			if term.ModifierName == "redirect" && redirect == nil {
				t := term
				redirect = &t
			}
			continue
		}

		if e.lookups >= LookupLimit && mechanismTable[term.Kind].costsLookup {
			e.recordLimitExceeded(domain)
			node := e.appendNode(domain, term, depth, mechanismTable[term.Kind].costsLookup, false, PermError, nil)
			return PermError, node, nil
		}

		matched, mechVerdict, matchErr := e.evaluateMechanism(ctx, domain, term, depth, clientIP)
		spec := mechanismTable[term.Kind]
		if spec.costsLookup {
			e.lookups++
		}
		node := e.appendNode(domain, term, depth, spec.costsLookup, matched, mechVerdict, matchErr)

		if matchErr != nil {
			return mechVerdict, node, nil
		}
		if matched {
			return mechVerdict, node, nil
		}
	}

	if redirect != nil {
		return e.evaluateRedirect(ctx, domain, *redirect, depth, clientIP)
	}

	return None, nil, nil
}

func (e *evaluator) evaluateRedirect(ctx context.Context, fromDomain string, term Mechanism, depth int, clientIP netip.Addr) (Verdict, *Node, error) {
	if e.lookups >= LookupLimit {
		e.recordLimitExceeded(fromDomain)
		node := e.appendNode(fromDomain, term, depth, true, false, PermError, nil)
		return PermError, node, nil
	}
	e.lookups++
	target, macroErr := e.expandMacros(term.Domain, fromDomain, clientIP)
	if macroErr != nil {
		node := e.appendNode(fromDomain, term, depth, true, false, PermError, macroErr)
		return PermError, node, nil
	}

	verdict, matchedInner, err := e.evaluateDomain(ctx, target, depth+1, clientIP)
	if err != nil {
		return TempError, nil, err
	}
	if verdict == None {
		verdict = PermError
	}
	node := e.appendNode(fromDomain, term, depth, true, true, verdict, nil)
	if matchedInner != nil {
		return verdict, matchedInner, nil
	}
	return verdict, node, nil
}

// fetchRecord resolves domain's unique SPF TXT record. done is true when
// the caller should stop with the returned Verdict immediately (no record,
// ambiguous multiple records, or a DNS failure); terms is only meaningful
// when done is false.
func (e *evaluator) fetchRecord(ctx context.Context, domain string, depth int) (terms []Mechanism, verdict Verdict, done bool) {
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		if resolve.IsTemporary(err) {
			return nil, TempError, true
		}
		return nil, None, true
	}

	var spfTXT string
	count := 0
	for _, t := range txts {
		if IsSPFRecord(t) {
			spfTXT = t
			count++
		}
	}
	if count == 0 {
		return nil, None, true
	}
	if count > 1 {
		return nil, PermError, true
	}

	parsed, err := ParseRecord(spfTXT)
	if err != nil {
		return nil, PermError, true
	}
	return parsed, None, false
}

func (e *evaluator) evaluateMechanism(ctx context.Context, domain string, term Mechanism, depth int, clientIP netip.Addr) (matched bool, verdict Verdict, err error) {
	if term.Kind == MechInclude {
		return e.evaluateInclude(ctx, domain, term, depth, clientIP)
	}

	spec, ok := mechanismTable[term.Kind]
	if !ok || spec.match == nil {
		return false, PermError, fmt.Errorf("spf: unknown mechanism %q", term.Raw)
	}
	m, matchErr := spec.match(ctx, e, domain, term, clientIP)
	if matchErr != nil {
		if resolve.IsTemporary(matchErr) {
			return false, TempError, matchErr
		}
		return false, PermError, matchErr
	}
	if m {
		return true, term.Qualifier.Verdict(), nil
	}
	return false, None, nil
}

// evaluateInclude implements RFC 7208 §5.2's include-result translation
// table: a pass inside the included record makes the include match, taking
// the include's own Qualifier rather than the included pass's. fail,
// softfail and neutral inside mean the include itself does not match and
// evaluation of the including record continues to its next term. A
// temperror inside propagates as temperror; a permerror inside, or a
// nonexistent (none) included domain, propagates as permerror. This
// distinction (result of the include vs. verdict it would have produced
// standalone) is the part most often implemented as a bare fall-through.
func (e *evaluator) evaluateInclude(ctx context.Context, fromDomain string, term Mechanism, depth int, clientIP netip.Addr) (matched bool, verdict Verdict, err error) {
	target, macroErr := e.expandMacros(term.Domain, fromDomain, clientIP)
	if macroErr != nil {
		return false, PermError, macroErr
	}
	innerVerdict, _, evalErr := e.evaluateDomain(ctx, target, depth+1, clientIP)
	if evalErr != nil {
		return false, TempError, evalErr
	}
	switch innerVerdict {
	case Pass:
		return true, term.Qualifier.Verdict(), nil
	case Fail, SoftFail, Neutral:
		return false, None, nil
	case None:
		return false, PermError, fmt.Errorf("spf: include target %q has no spf record", target)
	case PermError:
		return false, PermError, fmt.Errorf("spf: include target %q is a permerror", target)
	case TempError:
		return false, TempError, fmt.Errorf("spf: include target %q is a temperror", target)
	default:
		return false, PermError, fmt.Errorf("spf: include target %q produced an unusable result", target)
	}
}

func (e *evaluator) appendNode(domain string, term Mechanism, depth int, costsLookup, matched bool, verdict Verdict, err error) *Node {
	node := &Node{
		Domain:      domain,
		Term:        term,
		Depth:       depth,
		CostsLookup: costsLookup,
		Matched:     matched,
		Verdict:     verdict,
		Err:         err,
	}
	e.tree.Nodes = append(e.tree.Nodes, node)
	return node
}

func (e *evaluator) recordLimitExceeded(domain string) {
	e.findings = append(e.findings, Finding{
		Kind:    FindingLookupLimitExceeded,
		Domain:  domain,
		Message: fmt.Sprintf("spf: lookup limit of %d dns-querying mechanisms exceeded while evaluating %s", LookupLimit, domain),
	})
}

func (e *evaluator) recordSecondaryLimitExceeded(kind MechanismKind, domain string, total int) {
	e.findings = append(e.findings, Finding{
		Kind:   FindingSecondaryLimitExceeded,
		Domain: domain,
		Message: fmt.Sprintf(
			"spf: %s mechanism at %s resolved %d hosts, more than the secondary limit of %d; extras were ignored",
			kind, domain, total, SecondaryLookupLimit,
		),
	})
}

func matchAll(_ context.Context, _ *evaluator, _ string, _ Mechanism, _ netip.Addr) (bool, error) {
	return true, nil
}

func matchIP4(_ context.Context, _ *evaluator, _ string, term Mechanism, clientIP netip.Addr) (bool, error) {
	return matchIPLiteral(term, clientIP)
}

func matchIP6(_ context.Context, _ *evaluator, _ string, term Mechanism, clientIP netip.Addr) (bool, error) {
	return matchIPLiteral(term, clientIP)
}

func matchIPLiteral(term Mechanism, clientIP netip.Addr) (bool, error) {
	if !clientIP.IsValid() {
		return false, nil
	}
	spec := term.Domain
	if !strings.Contains(spec, "/") {
		addr, err := netip.ParseAddr(spec)
		if err != nil {
			return false, fmt.Errorf("spf: %s: %w", term.Raw, err)
		}
		return addr.Unmap() == clientIP, nil
	}
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return false, fmt.Errorf("spf: %s: %w", term.Raw, err)
	}
	return prefix.Contains(clientIP), nil
}

func matchA(ctx context.Context, e *evaluator, domain string, term Mechanism, clientIP netip.Addr) (bool, error) {
	target := domain
	if term.Domain != "" {
		expanded, macroErr := e.expandMacros(term.Domain, domain, clientIP)
		if macroErr != nil {
			return false, macroErr
		}
		target = expanded
	}
	addrs, err := e.resolver.LookupAddr(ctx, target)
	if err != nil {
		if resolve.IsNotFound(err) || resolve.IsNoRecords(err) {
			return false, nil
		}
		return false, err
	}
	return addrsContain(addrs, clientIP, term), nil
}

func matchMX(ctx context.Context, e *evaluator, domain string, term Mechanism, clientIP netip.Addr) (bool, error) {
	target := domain
	if term.Domain != "" {
		expanded, macroErr := e.expandMacros(term.Domain, domain, clientIP)
		if macroErr != nil {
			return false, macroErr
		}
		target = expanded
	}
	mxs, err := e.resolver.LookupMX(ctx, target)
	if err != nil {
		if resolve.IsNotFound(err) || resolve.IsNoRecords(err) {
			return false, nil
		}
		return false, err
	}
	total := len(mxs)
	if total > SecondaryLookupLimit {
		e.recordSecondaryLimitExceeded(MechMX, target, total)
		mxs = mxs[:SecondaryLookupLimit]
	}
	for _, mx := range mxs {
		addrs, aErr := e.resolver.LookupAddr(ctx, mx.Host)
		if aErr != nil {
			if resolve.IsNotFound(aErr) || resolve.IsNoRecords(aErr) {
				continue
			}
			return false, aErr
		}
		if addrsContain(addrs, clientIP, term) {
			return true, nil
		}
	}
	return false, nil
}

func matchPTR(ctx context.Context, e *evaluator, domain string, term Mechanism, clientIP netip.Addr) (bool, error) {
	if !clientIP.IsValid() {
		return false, nil
	}
	target := domain
	if term.Domain != "" {
		expanded, macroErr := e.expandMacros(term.Domain, domain, clientIP)
		if macroErr != nil {
			return false, macroErr
		}
		target = expanded
	}
	names, err := e.resolver.LookupPTR(ctx, clientIP)
	if err != nil {
		if resolve.IsNotFound(err) || resolve.IsNoRecords(err) {
			return false, nil
		}
		return false, err
	}
	if len(names) > SecondaryLookupLimit {
		e.recordSecondaryLimitExceeded(MechPTR, target, len(names))
		names = names[:SecondaryLookupLimit]
	}
	for _, name := range names {
		addrs, aErr := e.resolver.LookupAddr(ctx, name)
		if aErr != nil {
			continue
		}
		if !addrsContain(addrs, clientIP, Mechanism{}) {
			continue
		}
		n := strings.TrimSuffix(strings.ToLower(name), ".")
		t := strings.TrimSuffix(strings.ToLower(target), ".")
		if n == t || strings.HasSuffix(n, "."+t) {
			return true, nil
		}
	}
	return false, nil
}

func matchExists(ctx context.Context, e *evaluator, domain string, term Mechanism, clientIP netip.Addr) (bool, error) {
	target, macroErr := e.expandMacros(term.Domain, domain, clientIP)
	if macroErr != nil {
		return false, macroErr
	}
	_, err := e.resolver.LookupAddr(ctx, target)
	if err != nil {
		if resolve.IsNotFound(err) || resolve.IsNoRecords(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func addrsContain(addrs []netip.Addr, clientIP netip.Addr, term Mechanism) bool {
	if !clientIP.IsValid() {
		return false
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			if term.HasCIDR4 {
				bits := term.CIDR4
				p := netip.PrefixFrom(a, bits)
				if p.Contains(clientIP) {
					return true
				}
				continue
			}
			if a == clientIP {
				return true
			}
		} else {
			if term.HasCIDR6 {
				bits := term.CIDR6
				p := netip.PrefixFrom(a, bits)
				if p.Contains(clientIP) {
					return true
				}
				continue
			}
			if a == clientIP {
				return true
			}
		}
	}
	return false
}
