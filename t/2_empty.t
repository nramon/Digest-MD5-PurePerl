use strict;
use Test;

BEGIN {
	plan tests => 1
}

use Digest::MD5::PurePerl;

# Empty input.
ok(md5(""), "d41d8cd98f00b204e9800998ecf8427e")

