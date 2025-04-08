package awstools

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider() *schema.Provider {
	provider := &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"ssm_command": resourceCommand(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
		Schema: map[string]*schema.Schema{
			"assume_role": assumeRoleSchema(),
			"region": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The region where AWS operations will take place. Examples\n" +
					"are us-east-1, us-west-2, etc.", // lintignore:AWSAT003,
			},
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
		tflog.Info(ctx, "ConfigureContextFunc")
		return configure(ctx, d)
	}

	return provider
}

// configure
func configure(ctx context.Context, d *schema.ResourceData) (*AwsClients, diag.Diagnostics) {
	var assumeRole []awsbase.AssumeRole
	diags := make([]diag.Diagnostic, 0)

	if v, ok := d.GetOk("assume_role"); ok {
		tflog.Info(ctx, "detected assume_role configuration provided by user")
		v := v.([]any)
		if len(v) == 1 {
			if v[0] == nil {
				return nil, diag.Errorf("role_arn")
			} else {
				l := v[0].(map[string]any)
				if s, ok := l["role_arn"]; !ok || s == "" {
					return nil, diag.Errorf("role_arn")
				} else {
					tflog.Info(ctx, "detected role_arn configuration provided by user")
					ar, dg := expandAssumeRoles(ctx, v)
					diags = append(diags, dg...)
					if dg.HasError() {
						return nil, diags
					}
					assumeRole = ar
				}
			}
		} else if len(v) > 1 {
			ar, dg := expandAssumeRoles(ctx, v)
			diags = append(diags, dg...)
			if dg.HasError() {
				return nil, diags
			}
			assumeRole = ar
		}
	}

	if len(assumeRole) > 1 {
		return nil, diag.Errorf("Only 1 assume_role is supported")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	if region, ok := d.GetOk("region"); ok {
		tflog.Info(ctx, "detected region configuration provided by user", map[string]interface{}{"region": region})
		cfg.Region = region.(string)
	}

	if len(assumeRole) == 1 {
		stsSvc := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsSvc, assumeRole[0].RoleARN, func(options *stscreds.AssumeRoleOptions) {
			if len(assumeRole) != 1 {
				return
			}
			options.ExternalID = &assumeRole[0].ExternalID
			options.RoleARN = assumeRole[0].RoleARN
		})

		cfg.Credentials = aws.NewCredentialsCache(creds)
	}

	return &AwsClients{
		ec2Client: ec2.NewFromConfig(cfg),
		ssmClient: ssm.NewFromConfig(cfg),
		s3Client:  s3.NewFromConfig(cfg),
	}, nil
}

func expandAssumeRoles(ctx context.Context, tfList []any) (result []awsbase.AssumeRole, diags diag.Diagnostics) {
	result = make([]awsbase.AssumeRole, len(tfList))

	for i, v := range tfList {
		if ar, ok := v.(map[string]any); ok {
			x, d := expandAssumeRole(ctx, ar)
			diags = append(diags, d...)
			if d.HasError() {
				return result, diags
			}
			result[i] = x
			tflog.Info(ctx, "assume_role configuration set", map[string]any{
				"tf_aws.assume_role.index":           i,
				"tf_aws.assume_role.role_arn":        result[i].RoleARN,
				"tf_aws.assume_role.session_name":    result[i].SessionName,
				"tf_aws.assume_role.external_id":     result[i].ExternalID,
				"tf_aws.assume_role.source_identity": result[i].SourceIdentity,
			})
		} else {
			return result, diags
		}
	}

	return result, diags
}

func expandAssumeRole(_ context.Context, tfMap map[string]any) (result awsbase.AssumeRole, diags diag.Diagnostics) {
	if v, ok := tfMap["role_arn"].(string); ok && v != "" {
		result.RoleARN = v
	} else {
		return result, diag.Errorf("role_arn")
	}

	if v, ok := tfMap["duration"].(string); ok && v != "" {
		duration, _ := time.ParseDuration(v)
		result.Duration = duration
	}

	if v, ok := tfMap["external_id"].(string); ok && v != "" {
		result.ExternalID = v
	}

	if v, ok := tfMap["policy"].(string); ok && v != "" {
		result.Policy = v
	}

	if v, ok := tfMap["session_name"].(string); ok && v != "" {
		result.SessionName = v
	}

	if v, ok := tfMap["source_identity"].(string); ok && v != "" {
		result.SourceIdentity = v
	}

	return result, diags
}
