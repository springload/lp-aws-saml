package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/springload/lp-aws-saml/lastpassaws"
	cookiejar "github.com/vinhjaxt/persistent-cookiejar"
	"golang.org/x/crypto/ssh/terminal"
)

var rootCmd = &cobra.Command{
	Use:   "lp-aws-saml",
	Short: "Temporary Credentials for AWS CLI for LastPass SAML login",
	Long:  "Get temporary AWS credentials when using LastPass as a SAML login for AWS",
	Run: func(cmd *cobra.Command, args []string) {

		quiet := viper.GetBool("quiet")
		samlConfigID := viper.GetString("saml_config_id")
		samlIdentityURL := viper.GetString("saml_identity_url")

		username := viper.GetString("username")
		if !quiet {
			log.Println("Logging in with: ", username)
		}

		options := cookiejar.Options{
			Filename: fmt.Sprintf("%s/.aws/lp_cookies", lastpassaws.HomeDir()),
		}
		jar, _ := cookiejar.New(&options)
		session := &http.Client{
			Jar: jar,
		}

		var assertion string
		var err error
		// Attempt to use stored cookies
		for {
			var samlURL string
			attemptSaml := true
			if samlIdentityURL != "" {
				err = lastpassaws.GetLastpassIdentitySession(session)
				if err != nil {
					log.Printf("Cannot get Lastpass Identity: %s", err)
					attemptSaml = false
				}
				samlURL = samlIdentityURL
			} else {
				samlURL = lastpassaws.LastPassServer + "/saml/launch/cfg/" + samlConfigID
			}

			if attemptSaml {
				assertion, err = lastpassaws.SamlToken(session, samlURL)
				if err != nil {
					log.Fatalf("Can't get the saml: %s", err)
				}
				if assertion != "" {
					break
				}
			}

			log.Println("Don't have session, trying to log in")

			fmt.Print("Lastpass Password: ")
			bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			fmt.Print("Lastpass 2FA: ")
			byteOtp, _ := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()

			password := string(bytePassword)
			otp := string(byteOtp)

			if err := lastpassaws.Login(session, username, password, otp); err != nil {
				log.Fatalf("Invalid Credentials: %s", err)
				return
			} else {
				jar.Save()
			}

		}

		roles := lastpassaws.SamlRoles(assertion)
		if len(roles) == 0 {
			log.Printf("No roles available for %s!\n", username)
			os.Exit(1)
			return
		}
		role := lastpassaws.PromptForRole(roles)

		profileName := viper.GetString("profile_name")
		duration := viper.GetInt("duration")

		response, err := lastpassaws.AssumeAWSRole(assertion, role[0], role[1], duration)
		if err != nil {
			log.Fatalf("Cannot assume role: %s", err)
			os.Exit(1)
		}
		lastpassaws.SetAWSProfile(profileName, response)

		if !quiet {
			fmt.Println()
			fmt.Printf("A new AWS CLI profile '%s' has been added.\n", profileName)
			fmt.Println("You may now invoke the aws CLI tool as follows:")
			fmt.Println()
			fmt.Printf("    aws --profile %s [...] \n", profileName)
			fmt.Println()
			fmt.Printf("This token expires in %.2d hours.\n", (duration / 60 / 60))
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringP("username", "u", "", "LastPass username")
	rootCmd.PersistentFlags().StringP("saml_config_id", "s", "", "LastPass saml config ID")
	rootCmd.PersistentFlags().StringP("profile_name", "p", "default", "AWS profile to set in ~/.aws/credentials")
	rootCmd.PersistentFlags().IntP("duration", "d", 3600, "Duration (in seconds) for AWS credentials to be valid")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Silence output unless error")

	viper.BindPFlag("username", rootCmd.PersistentFlags().Lookup("username"))
	viper.BindPFlag("saml_config_id", rootCmd.PersistentFlags().Lookup("saml_config_id"))
	viper.BindPFlag("profile_name", rootCmd.PersistentFlags().Lookup("profile_name"))
	viper.BindPFlag("duration", rootCmd.PersistentFlags().Lookup("duration"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
}

func initConfig() {
	viper.SetConfigName("lp_config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(fmt.Sprintf("%s/.aws/", lastpassaws.HomeDir()))

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}
}
