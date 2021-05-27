# Promote useful stuff to toplevel
from __future__ import absolute_import

'''
import sys
sys.path.append("../pwn_debug/pwn_debug")
from pwn_debug.fmtstr import *
from pwn_debug.membp import *
from pwn_debug.ret2dl_resolve import *
'''

from pwn_debug.IO_FILE_plus import *
from pwn_debug.pwn_debug import *
from pwn_debug.pwn_start import *
from pwn_debug.misc import * 

'''
if sys.version_info.major==2:
    from pwn_debug.IO_FILE_plus import *
    from pwn_debug.fmtstr import *
    from pwn_debug.membp import *
    from pwn_debug.misc import * 
    from pwn_debug.ret2dl_resolve import *

    from pwn_debug.pwn_debug import *
    from pwn_debug.pwn_start import *
else:
    from IO_FILE_plus import *
    from fmtstr import *
    from membp import *
    from misc import * 
    from ret2dl_resolve import *

    from pwn_debug import *
    from pwn_start import *
'''


