// Command capybari-identity runs this capability on its own.
package main

import (
	identity "github.com/capybari-repo/capybari-analyzer-identity"
	"github.com/capybari-repo/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, identity.New()) }
