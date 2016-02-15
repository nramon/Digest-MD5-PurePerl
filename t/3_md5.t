use strict;
use Test;

BEGIN {
	plan tests => 3
}

use Digest::MD5::PurePerl;

# Short string.
ok(md5("Philip J. Fry"), "773ab0706b0d39672573f1da95b3a9b8");

# 1025 byte string.
ok(md5("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque laoreet ligula a dui ultrices lacinia. Aliquam erat volutpat. Integer fringilla nunc vitae dapibus euismod. Vestibulum nec neque sit amet urna volutpat aliquet eget in odio. Morbi vitae neque tincidunt, hendrerit ligula venenatis, consequat ipsum. Nulla ultricies, sem et consectetur sagittis, mauris lacus dapibus arcu, eu porttitor nunc risus nec neque. Nulla eu varius lorem, quis finibus nibh. Maecenas laoreet tempus eros, non suscipit augue placerat eu. Maecenas dignissim feugiat magna, vitae lobortis nunc pharetra sit amet. Praesent sed erat sed metus aliquam viverra. Ut ut elementum nunc. Etiam viverra quis nibh sit amet ultricies. Ut egestas ligula a molestie semper. Etiam lobortis mi ac diam ornare vestibulum. Aenean posuere nisl eget augue bibendum, nec mollis ligula imperdiet. Suspendisse varius sodales sem non scelerisque. Ut felis nunc, egestas a semper id, tempor non diam. Sed faucibus elementum orci nec aliquet. Nulla ac orci aliquam."), "ecbc249e4735144a5027d06703e4e17b");

# Binary data.
ok(md5(pack("c4", 0x01, 0x02, 0x03, 0x04)), "08d6c05a21512a79a1dfeb9d2a8f262f");
