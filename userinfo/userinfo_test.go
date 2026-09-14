package userinfo_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"huxim/libs/clerkauth/userinfo"
)

func TestUserInfo_ZeroValue(t *testing.T) {
	var u userinfo.UserInfo
	require.Empty(t, u.UserID)
	require.Equal(t, userinfo.AuthType(""), u.AuthType)
	require.NotEqual(t, userinfo.AuthTypeClerk, userinfo.AuthTypeToken)
}
