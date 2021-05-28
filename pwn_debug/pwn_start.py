#! coding=utf-8
import argparse
from pwn import *
from pwn_debug import pwn_debug


def isNum(num):
    try:
        ret = eval(num)
        if isinstance(ret, int) or isinstance(ret, long):
            return True
        return False
    except Exception:
        return False

def args_bool(string):
    if string == 'True' or string == "False":
        return eval(string)
    if string == '1':
        return True
    if string == '0':
        return False
    raise argparse.ArgumentTypeError("input arg:%s must be True/1 or False/0" % string)

def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name', nargs="*", type=str, help='input ELF file name')
    parser.add_argument('-l', '--libc', nargs="?", type=str, help='glibc version or file path')
    parser.add_argument('-ld', '--ld', nargs="?", type=str, help='ld file path')
    parser.add_argument('-s', '--so', nargs="*", type=str, help='addtion shared object file')
    parser.add_argument('-r', '--remote', type=str, help='remote ip address and port, like: "192.169.1.1:9999"')

    debug_help = "Set GDB configuration, special: number means breakpoint"
    parser.add_argument('-d', '--debug', nargs='*', type=str, help=debug_help)

    parser.add_argument('-g', '--gdb', nargs="?", type=args_bool, default=False, help="replace gdb.attach by gdb.debug")

    log_level_help = "log_level must be one of ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']"
    parser.add_argument('-log', '--log_level', nargs="?", type=str, default="debug", help=log_level_help)
    parser.add_argument('-f', '--fork_child', nargs="?", type=args_bool, default=True, help="whether set follow-fork-mode child, False is parent")

    args = parser.parse_args()
    print(args)
    return args


class pwn_start(object):
    def __init__(self, args):
        self.name = args.name
        self.libc = args.libc
        self.remote = args.remote
        self.scripts = args.debug
        self.ld = args.ld
        self.so = args.so
        self.gdb = args.gdb
        
        if args.fork_child is None or args.fork_child is True:
            self.fork_follow = "child"
        else:
            self.fork_follow = "parent"

        self.pdbg=pwn_debug(self.name)
        
        preload = self.so
        if isinstance(self.so, list):
            preload = " ".join(self.so)
        self.pdbg.set_libc(self.libc, self.ld, {"LD_PRELOAD":preload})
        if self.so is not None:
            self.pdbg.set_so(self.so)
        self.pdbg.context.log_level = args.log_level

    def start(self):
        if self.remote is not None:
            return self.start_remote()
        if self.gdb is None or self.gdb is True:
            return self.start_gdb()
        return self.start_local()

    def start_local(self):
        log.info("start local")
        p = self.pdbg.run_local()
        return p

    def start_gdb(self):
        log.info("start gdb")
        p = self.pdbg.run_gdb(self.scripts, self.fork_follow)
        return p

    def start_remote(self):
        log.info("start remote")
        self.ip, port = self.remote.split(":")
        self.port = eval(port)
        p = self.pdbg.run_remote(self.ip, self.port)
        return p
    
    def debug(self):
        if not self.remote:
            self.pdbg.debug(self.scripts, self.fork_follow)

"""
if __name__ == "__main__":
    args = getArgs()
    ps = pwn_start(args)
    p = ps.start()
    p.interactive()

"""
