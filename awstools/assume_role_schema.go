package awstools

import (
	"fmt"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func assumeRoleSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"duration": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "The duration, between 15 minutes and 12 hours, of the role session. Valid time units are ns, us (or µs), ms, s, h, or m.",
					ValidateFunc: validAssumeRoleDuration,
				},
				"external_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "A unique identifier that might be required when you assume a role in another account.",
					ValidateFunc: validation.All(
						validation.StringLenBetween(2, 1224),
						validation.StringMatch(regexache.MustCompile(`[\w+=,.@:\/\-]*`), ""),
					),
				},
				"policy": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.",
					ValidateFunc: validation.StringIsJSON,
				},
				"role_arn": {
					Type:         schema.TypeString,
					Optional:     true, // For historical reasons, we allow an empty `assume_role` block
					Description:  "Amazon Resource Name (ARN) of an IAM Role to assume prior to making API calls.",
					ValidateFunc: ValidARN,
				},
				"session_name": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "An identifier for the assumed role session.",
					ValidateFunc: validAssumeRoleSessionName,
				},
				"source_identity": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Source identity specified by the principal assuming the role.",
					ValidateFunc: validAssumeRoleSourceIdentity,
				},
			},
		},
	}
}

// validAssumeRoleDuration validates a string can be parsed as a valid time.Duration
// and is within a minimum of 15 minutes and maximum of 12 hours
func validAssumeRoleDuration(v any, k string) (ws []string, errors []error) {
	duration, err := time.ParseDuration(v.(string))

	if err != nil {
		errors = append(errors, fmt.Errorf("%q cannot be parsed as a duration: %w", k, err))
		return
	}

	if duration.Minutes() < 15 || duration.Hours() > 12 {
		errors = append(errors, fmt.Errorf("duration %q must be between 15 minutes (15m) and 12 hours (12h), inclusive", k))
	}

	return
}

var validAssumeRoleSessionName = validation.All(
	validation.StringLenBetween(2, 64),
	validation.StringMatch(regexache.MustCompile(`[\w+=,.@\-]*`), ""),
)

var validAssumeRoleSourceIdentity = validation.All(
	validation.StringLenBetween(2, 64),
	validation.StringMatch(regexache.MustCompile(`[\w+=,.@\-]*`), ""),
)

// ValidARN validates that a string value matches a generic ARN format
var ValidARN = ValidARNCheck()
var accountIDRegexp = regexache.MustCompile(`^(aws|aws-managed|third-party|aws-marketplace|\d{12}|cw.{10})$`)
var partitionRegexp = regexache.MustCompile(`^aws(-[a-z]+)*$`)
var regionRegexp = regexache.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d{1,2}$`)

type ARNCheckFunc func(any, string, arn.ARN) ([]string, []error)

// ValidARNCheck validates that a string value matches an ARN format with additional validation on the parsed ARN value
// It must:
// * Be parseable as an ARN
// * Have a valid partition
// * Have a valid region
// * Have either an empty or valid account ID
// * Have a non-empty resource part
// * Pass the supplied checks
func ValidARNCheck(f ...ARNCheckFunc) schema.SchemaValidateFunc {
	return func(v any, k string) (ws []string, errors []error) {
		value, ok := v.(string)
		if !ok {
			errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
			return ws, errors
		}

		if value == "" {
			return ws, errors
		}

		parsedARN, err := arn.Parse(value)

		if err != nil {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: %s", k, value, err))
			return ws, errors
		}

		if parsedARN.Partition == "" {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing partition value", k, value))
		} else if !partitionRegexp.MatchString(parsedARN.Partition) {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid partition value (expecting to match regular expression: %s)", k, value, partitionRegexp))
		}

		if parsedARN.Region != "" && !regionRegexp.MatchString(parsedARN.Region) {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid region value (expecting to match regular expression: %s)", k, value, regionRegexp))
		}

		if parsedARN.AccountID != "" && !accountIDRegexp.MatchString(parsedARN.AccountID) {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid account ID value (expecting to match regular expression: %s)", k, value, accountIDRegexp))
		}

		if parsedARN.Resource == "" {
			errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing resource value", k, value))
		}

		for _, f := range f {
			w, e := f(v, k, parsedARN)
			ws = append(ws, w...)
			errors = append(errors, e...)
		}

		return ws, errors
	}
}
