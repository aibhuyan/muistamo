module muistamo.dev/muistamo

go 1.27.0

toolchain go1.27.3

// The console is TypeScript; its node_modules can contain stray Go packages.
ignore ./console

tool github.com/atombender/go-jsonschema

require (
	github.com/goccy/go-yaml v1.19.2
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/spf13/cobra v1.10.2
)

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/atombender/go-jsonschema v0.24.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/sanity-io/litter v1.5.8 // indirect
	github.com/sosodev/duration v1.4.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/text v0.14.0 // indirect
)
