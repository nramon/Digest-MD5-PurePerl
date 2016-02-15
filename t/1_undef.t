use strict;
use Test;

BEGIN {
	plan tests => 1
}

use Digest::MD5::PurePerl;

# Undefined input.
ok(md5(undef), "")

