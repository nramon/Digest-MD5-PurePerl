use strict;
use warnings;
use Test::More tests => 5;

use Digest::MD5::PurePerl;

# Internal helper: 32-bit left rotation.
is(Digest::MD5::PurePerl::leftrotate(0x80000000, 1), 0x00000001, 'bit wraps around');
is(Digest::MD5::PurePerl::leftrotate(0x00000001, 31), 0x80000000, 'rotate by 31');
is(Digest::MD5::PurePerl::leftrotate(0x12345678, 8), 0x34567812, 'rotate by 8');
is(Digest::MD5::PurePerl::leftrotate(0xFFFFFFFF, 13), 0xFFFFFFFF, 'all ones');
is(Digest::MD5::PurePerl::leftrotate(0, 7), 0, 'zero');
