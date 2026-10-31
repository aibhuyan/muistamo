package entra

// HUMAN REVIEW REQUIRED: matching an HR person to their Entra user (docs/obo-retrieval-plan.md,
// PR A). The match decides which person an Entra token speaks for, so it is exact or nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"

	"github.com/google/uuid"
)

const usersCollection = "users"

// employeeIDPattern is what an HR person id must look like to be compared with an Entra
// employeeId (at most 16 characters in Entra). Anything else is never sent to Graph, so no
// person id can change the meaning of the OData filter it is quoted into.
var employeeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,16}$`)

// UserMatch is the outcome of one lookup: exactly one user, none, or more than one.
type UserMatch struct {
	Status   string // "matched", "unmatched" or "ambiguous"
	ObjectID uuid.UUID
}

// LookupUserByEmployeeID finds the Entra user whose employeeId equals the HR person id exactly.
// A person id that cannot be an employeeId is unmatched without a request.
func (c *Client) LookupUserByEmployeeID(ctx context.Context, tenant uuid.UUID, employeeID string) (UserMatch, error) {
	if err := c.scope(ctx, tenant); err != nil {
		return UserMatch{}, err
	}
	if !employeeIDPattern.MatchString(employeeID) {
		return UserMatch{Status: "unmatched"}, nil
	}
	query := url.Values{"$filter": {"employeeId eq '" + employeeID + "'"}, "$select": {"id,employeeId"}, "$count": {"true"}, "$top": {"2"}}
	id := uuid.New()
	reply, err := c.graph(ctx, "user-lookup", http.MethodGet, usersCollection+"?"+query.Encode(), nil, id)
	if err != nil {
		return UserMatch{}, err
	}
	if reply.status != http.StatusOK {
		return UserMatch{}, reply.failure("user-lookup", false, id)
	}
	var page struct {
		Value []struct {
			ID         string `json:"id"`
			EmployeeID string `json:"employeeId"`
		} `json:"value"`
		Count *int `json:"@odata.count"`
	}
	if err := json.Unmarshal(reply.body, &page); err != nil || page.Count == nil {
		return UserMatch{}, &Error{Operation: "user-lookup", Code: "lookup_inconclusive", RequestID: id, kind: ErrProvider}
	}
	// The page holds every match (count ≤ 2) or the first two of more: anything else is not an
	// answer to this query.
	if n := len(page.Value); n > 2 || (*page.Count != n && (*page.Count <= 2 || n != 2)) {
		return UserMatch{}, &Error{Operation: "user-lookup", Code: "lookup_inconclusive", RequestID: id, kind: ErrProvider}
	}
	// Graph's comparison may ignore case; only an exact employeeId counts as this person.
	var exact []uuid.UUID
	for _, user := range page.Value {
		objectID, valid := canonicalID(user.ID)
		if !valid {
			return UserMatch{}, &Error{Operation: "user-lookup", Code: "lookup_inconclusive", RequestID: id, kind: ErrProvider}
		}
		if user.EmployeeID == employeeID {
			exact = append(exact, objectID)
		}
	}
	switch {
	case *page.Count > 1 || len(exact) > 1:
		return UserMatch{Status: "ambiguous"}, nil
	case len(exact) == 1:
		return UserMatch{Status: "matched", ObjectID: exact[0]}, nil
	default:
		return UserMatch{Status: "unmatched"}, nil
	}
}
