# pwn_debug

修改自[ray-cp](https://github.com/ray-cp/pwn_debug)版本的pwn_debug。安装以及build方法与原版本相同，主要修改了pwn_debug.py以及添加了pwn_start.py两个脚本文件。

## normal usage

```python
from pwn_debug import *

def main():
    pdbg.debug(scripts)

if __name__ == "__main__":
    pdbg=pwn_debug("./test")
    # pdbg = pwn_debug(["./test", "arg1", "arg2"])
    pdbg.context.log_level = "debug"
    
    # set_libc can input pathto libc or available glibc_version in folder '/glibc/...'
    # pdbg.set_libc("2.31") 
    
    pdbg.set_libc("./libc-2.23.so", "./ld-2.23.so")
    
    pdbg.add_so("./libunicorn.so.1")
    # pdbg.add_so(["xxx", "yyy", "zzz"])	# more than one
    
    scripts = [0x23F9, "b vuln", "b test"]
    # run_local means run elf directly
    # run_debug means gdb.attach
    # run_gdb   means gdb.debug, it can break before main
    # run_remote(ip, port)
    # p = pdbg.run_gdb(scripts)  # it can be break before main
    # p = pdbg.run_debug(scripts, fork_follow="child")
    
    p = pdbg.run_local()
    p.interactive()
```



## pwn_start

```python
from pwn_debug import *

def main():
    pass

if __name__ == "__main__":
    args = getArgs()
    ps = pwn_start(args)
    p = ps.start()
    main()
    p.interactive()
```

```shell
> python xxx.py -h
usage: xxx.py [-h] [-n [NAME [NAME ...]]] [-l [LIBC]] [-ld [LD]]
              [-s [SO [SO ...]]] [-r REMOTE] [-d [DEBUG [DEBUG ...]]]
              [-g [GDB]] [-log [LOG_LEVEL]] [-f [FORK_CHILD]]

optional arguments:
  -h, --help            show this help message and exit
  -n [NAME [NAME ...]], --name [NAME [NAME ...]]
                        input ELF file name
  -l [LIBC], --libc [LIBC]
                        glibc version or file path
  -ld [LD], --ld [LD]   ld file path
  -s [SO [SO ...]], --so [SO [SO ...]]
                        addtion shared object file
  -r REMOTE, --remote REMOTE
                        remote ip address and port, like: "192.169.1.1:9999"
  -d [DEBUG [DEBUG ...]], --debug [DEBUG [DEBUG ...]]
                        Set GDB configuration, special: number means
                        breakpoint
  -g [GDB], --gdb [GDB]
                        replace gdb.attach by gdb.debug
  -log [LOG_LEVEL], --log_level [LOG_LEVEL]
                        log_level must be one of ['CRITICAL', 'DEBUG',
                        'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
  -f [FORK_CHILD], --fork_child [FORK_CHILD]
                        whether set follow-fork-mode child, False is parent
```

```python
from pwn_debug import *

def main():
    ps.debug()

if __name__ == "__main__":
    args = getArgs()
    args.name = "./test"	# ["./test", "arg1", "arg2"]
    args.debug = [0x23F9, "b vuln", "b test"]
    args.libc = "2.27"
    args.so = "./libunicorn.so.1"
    # args.libc = "./libc-2.27.so"
    # args.ld = "./ld-2.27.so"
    
    ps = pwn_start(args)
    # run_local or run_gdb or run_remote depend on args
    # debug should be called by self
    p = ps.start()
    main()
    p.interactive()
```

