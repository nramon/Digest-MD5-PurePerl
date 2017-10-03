# Copyright (C) 2009 Ramon Novoa <ramonnovoa@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA  02110-1301, USA.
package Digest::MD5::PurePerl;

use strict;
use warnings;
use vars qw($VERSION @ISA %EXPORT_TAGS @EXPORT_OK @EXPORT);

$VERSION = '1.0.1';

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use Digest::MD5::PurePerl ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
require Exporter;
@ISA = qw(Exporter AutoLoader);
%EXPORT_TAGS = ('all' => [ qw() ]);
@EXPORT_OK = (@{$EXPORT_TAGS{'all'}});
@EXPORT = qw(md5);

###############################################################################
###############################################################################
## Implementation of the MD5 message-digest algorithm.
###############################################################################
###############################################################################

# 2 to the power of 32.
use constant POW232 => 2**32;

# Fixed constants. See: https://en.wikipedia.org/wiki/MD5#Pseudocode
# S specifies the per-round shift amounts.
my @S = (
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
);

our @K = (
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
);

###############################################################################
# Return the MD5 checksum of the given string as a hex string.
# Pseudocode from: http://en.wikipedia.org/wiki/MD5#Pseudocode
###############################################################################
sub md5 {
	my $str = shift;

	# No input!
	if (!defined($str)) {
		return "";
	}

	# Note: All variables are unsigned 32 bits and wrap modulo 2^32 when
	# calculating.

	# Initialize variables.
	my $h0 = 0x67452301;
	my $h1 = 0xEFCDAB89;
	my $h2 = 0x98BADCFE;
	my $h3 = 0x10325476;

	# Pre-processing.
	my $msg = unpack ("B*", pack ("A*", $str));
	my $bit_len = length ($msg);

	# Append "1" bit to message.
	$msg .= '1';

	# Append "0" bits until message length in bits ≡ 448 (mod 512).
	$msg .= '0' while ((length ($msg) % 512) != 448);

	# Append bit /* bit, not byte */ length of unpadded message as 64-bit
	# little-endian integer to message.
	$msg .= unpack ("B32", pack ("V", $bit_len));
	# Do two 16 bit shifts, since the behaviour of a 32 bit shift on a 32 bit
	# integer is undefined.
	$msg .= unpack ("B32", pack ("V", ($bit_len >> 16) >> 16));

	# Process the message in successive 512-bit chunks.
	for (my $i = 0; $i < length ($msg); $i += 512) {

		my @w;
		my $chunk = substr ($msg, $i, 512);

		# Break chunk into sixteen 32-bit little-endian words w[i], 0 <= i <=
		# 15.
		for (my $j = 0; $j < length ($chunk); $j += 32) {
			push (@w, unpack ("V", pack ("B32", substr ($chunk, $j, 32))));
		}

		# Initialize hash value for this chunk.
		my $a = $h0;
		my $b = $h1;
		my $c = $h2;
		my $d = $h3;
		my $f;
		my $g;

		# Main loop.
		for (my $y = 0; $y < 64; $y++) {
			if ($y <= 15) {
				$f = $d ^ ($b & ($c ^ $d));
				$g = $y;
			}
			elsif ($y <= 31) {
				$f = $c ^ ($d & ($b ^ $c));
				$g = (5 * $y + 1) % 16;
			}
			elsif ($y <= 47) {
				$f = $b ^ $c ^ $d;
				$g = (3 * $y + 5) % 16;
			}
			else {
				$f = $c ^ ($b | (0xFFFFFFFF & (~ $d)));
				$g = (7 * $y) % 16;
			}

			my $temp = $d;
			$d = $c;
			$c = $b;
			$b = ($b + leftrotate (($a + $f + $K[$y] + $w[$g]) % POW232, $S[$y])) % POW232;
			$a = $temp;
		}

		# Add this chunk's hash to result so far.
		$h0 = ($h0 + $a) % POW232;
		$h1 = ($h1 + $b) % POW232;
		$h2 = ($h2 + $c) % POW232;
		$h3 = ($h3 + $d) % POW232;
	}

	# Digest := h0 append h1 append h2 append h3 #(expressed as little-endian)
	return unpack ("H*", pack ("V", $h0)) .
	       unpack ("H*", pack ("V", $h1)) .
	       unpack ("H*", pack ("V", $h2)) .
	       unpack ("H*", pack ("V", $h3));
}

###############################################################################
# MD5 leftrotate function. See: http://en.wikipedia.org/wiki/MD5#Pseudocode
###############################################################################
sub leftrotate {
	my ($x, $c) = @_;

	return (0xFFFFFFFF & ($x << $c)) | ($x >> (32 - $c));
}

1;
__END__

=head1 NAME

Digest::MD5::PurePerl - Pure Perl implementation of the MD5 algorithm.

=head1 SYNOPSIS

  use Digest::MD5::PurePerl;
  my $hash = md5("input string");

=head1 DESCRIPTION

This is a Pure Perl implementation of the MD5 message-digest algorithm (see:
http://en.wikipedia.org/wiki/MD5) that does not depend on any other modules.

=head2 Methods

=over 4

=item * md5()

Returns the MD5 hash of the given string as a hex string.

=back

=head1 AUTHOR

Ramon Novoa <ramonnovoa@gmail.com>

=head1 COPYRIGHT

Copyright (C) 2009 Ramon Novoa <ramonnovoa@gmail.com>

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA  02110-1301, USA.

=cut
