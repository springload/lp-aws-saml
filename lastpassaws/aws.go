package lastpassaws

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
)

// AssumeAWSRole returns a response from assuming a role on AWS STS
// and includes the required credentials
func AssumeAWSRole(assertion, roleArn, principalArn string, duration int) (*sts.AssumeRoleWithSAMLOutput, error) {

	input := sts.AssumeRoleWithSAMLInput{
		RoleArn:         aws.String(roleArn),
		PrincipalArn:    aws.String(principalArn),
		SAMLAssertion:   aws.String(assertion),
		DurationSeconds: aws.Int64(int64(duration)),
	}

	sess, err := session.NewSession()

	sts := sts.New(sess)
	resp, err := sts.AssumeRoleWithSAML(&input)
	if err != nil {
		log.Println("Error assuming role: ", err)
		return nil, err
	}
	return resp, nil
}

// SetAWSProfile saves the role credentials into ~/.aws/credentials
func SetAWSProfile(profileName string, response *sts.AssumeRoleWithSAMLOutput) {
	filename := fmt.Sprintf("%s/.aws/credentials", HomeDir())
	cfg, err := ini.Load(filename)
	if err != nil {
		log.Fatalf("Fail to read file: %v", err)
	}

	sec := cfg.Section(profileName)
	sec.Key("aws_access_key_id").SetValue(aws.StringValue(response.Credentials.AccessKeyId))
	sec.Key("aws_secret_access_key").SetValue(aws.StringValue(response.Credentials.SecretAccessKey))
	sec.Key("aws_session_token").SetValue(aws.StringValue(response.Credentials.SessionToken))

	cfg.SaveTo(filename)
}
