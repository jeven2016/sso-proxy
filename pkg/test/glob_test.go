package test

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
)

func TestGlob(t *testing.T) {
	g := glob.MustCompile("**/realms/**/departments-resources/?**")
	assert.True(t, g.Match("/realms/master/departments-resources/hello"))
	assert.True(t, g.Match("/proxy/iam/realms/master/departments-resources/test/one"))
}
