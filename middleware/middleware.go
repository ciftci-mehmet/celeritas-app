package middleware

import (
	"myapp/data"

	"github.com/ciftci-mehmet/celeritas"
)

type Middleware struct {
	App    *celeritas.Celeritas
	Models data.Models
}
