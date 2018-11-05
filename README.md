### LastPass x AWS x SAML = Headache for awscli?

`lp-aws-saml` allows you to use the `awscli` on your machine when your login to the aws console is via LastPass SAML login only.

It even supports 2FA and Yubikey OTP for your LastPass login and will store your LastPass session in `~/.aws/lp_cookies`
so you do not have to type the password every time you need new credentials.

```
$ lp-aws-saml -h
Get temporary AWS credentials when using LastPass as a SAML login for AWS

Usage:
  lp-aws-saml [flags]

Flags:
  -d, --duration int            Duration (in seconds) for AWS credentials to be valid (default 3600)
  -h, --help                    help for lp-aws-saml
  -p, --profile_name string     AWS profile to set in ~/.aws/credentials (default "default")
  -q, --quiet                   Silence output unless error
  -s, --saml_config_id string   LastPass saml config ID
  -u, --username string         LastPass username
```

All flags can be specified in a configuration file `~/.aws/lp_config.toml`

```toml
username = "email@example.com"
saml_config_id = "12345"
```

```
$ lp-aws-saml
Logging in with: email@example.com
Password: 
OTP: 
A new AWS CLI profile 'default' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile default [...]

This token expires in 1 hours.
```

You now have a new or updated entry in `~/.aws/credentials`

```ini
[default]
aws_access_key_id     = {YOUR_ACCESS_KEY_ID}
aws_secret_access_key = {YOUR_SECRET_ACCESS_KEY}
aws_session_token     = {YOUR_SESSION_TOKEN}
```

### Installation

For macOS you can install with brew:
```sh
brew install springload/tools/lp-aws-saml
```

There are `deb` and `rpm` packages and binaries for those who don't use packages. Just head up to the [releases](https://github.com/springload/lp-aws-saml/releases/latest) page.
