from pwn import *
import shutil
import os
from membp import membp
from ret2dl_resolve import ret2dl_resolve
import fmtstr

def getNum(num):
    try:
        if isinstance(num, int) or isinstance(num, long):
            return num
        ret = eval(num)
        if isinstance(ret, int) or isinstance(ret, long):
            return ret
        return None
    except Exception:
        return None


class pwn_debug(object):
    def __init__(self,pwn_name):
        self.args = []
        self.addso = set()
        if isinstance(pwn_name, list):
            self.pwn_name=pwn_name[0]
            if len(pwn_name) > 1:
                self.args = pwn_name[1:]
        else:
            self.pwn_name = pwn_name
        self.elf = ELF(self.pwn_name)
        self.pwn_path="/tmp/"+self.pwn_name.split("/")[-1]
        self.get_basic_info()
        log.info("ELF arch: %s"%self.arch)
        log.info("ELF endian: %s"%self.endian)

        ## get some class from pwn
        self.get_pwn_class()
        self.context.arch=self.arch
        self.context.endian=self.endian
        self.glibc_path_prefix = "/glibc/%s/" % ("x64" if self.arch=="amd64" else "x86")
        self.libc_path = None
        self.ld_path = None
        #self.set_default()

    # get class from pwn including: context
    def get_pwn_class(self):
        self.context=context

    def __getattr__(self,item):
        if item=="membp" and self.p_type=="remote":
            log.error("Can't use membp in remote mode")
            return None
        log.error("No %s in pwn_debug"%item)
        exit(0)

    def get_basic_info(self):
        if self.pwn_name:
            pwn_name=self.pwn_name
        else:
            pwn_name="/bin/dash"
        with open(pwn_name) as fd:
            if fd.read(4) =='\x7fELF':
                arch=u8(fd.read(1))
                if arch==2:
                    self.arch="amd64"
                elif arch==1:
                    self.arch="x86"
                else:
                    log.error("elf with a unknow arch")
                endian=u8(fd.read(1))
                if endian==2:
                    self.endian="big"
                elif endian==1:
                    self.endian="little"
                else:
                    log.error("elf with a unknow endian")

            else:
                log.error("not a elf file")
                exit(0)

    def set_so(self, so):
        if not isinstance(so, list):
            so = [so]
        for i in so:
            if os.path.exists(i):
                self.addso.add(os.path.dirname(os.path.realpath(i)))
            else:
                log.error("set additional so file: %s fail."%i)

    def get_libc_version(self, libc_name):
        self.libc = ELF(libc_name)
        mark = "stable release version "
        idx = self.libc.search("stable release version").next()
        assert idx > 0
        self.libc_version = self.libc.string(idx)[len(mark):len(mark)+4]
        log.info("Glibc version is " + self.libc_version)

    def set_glibc_path(self, libc_version):
        if self.arch=='amd64':
            self.libc_path='/glibc/x64/'+libc_version+'/lib/libc-'+libc_version+'.so'
        else:
            self.libc_path='/glibc/x86/'+libc_version+'/lib/libc-'+libc_version+'.so'

    def set_ld_path(self, libc_version):
        if self.arch=='amd64':
            self.ld_path='/glibc/x64/'+libc_version+'/lib/ld-'+libc_version+'.so'
        else:
            self.ld_path='/glibc/x86/'+libc_version+'/lib/ld-'+libc_version+'.so'

    def getldd(self, s):
        idx = s.find(" => ")
        if idx > 0:
            s = s[idx+4:]
        return s.split(" ")[0].strip()

    def fromldd(self):
        op = os.popen("ldd " + self.pwn_name)
        ldds = op.read().split("\n")
        findlibc = False
        findld = False
        for i in ldds:
            if not findlibc and i.find("libc.so.6") >= 0:
                self.libc_path = self.getldd(i)
                findlibc = True
            if not findld and i.find("/ld-") >= 0:
                self.ld_path = self.getldd(i)
                findld = True
            if findlibc and findld:
                break

    def set_libc(self, libc=None, ld=None, env={}):
        if libc is None or libc == "":
            self.fromldd()
            libc_name = os.readlink(self.libc_path)
            self.libc_version = libc_name[5:-3]
            self.libc = ELF(self.libc_path)
        elif libc.find("/") < 0 and os.path.exists(self.glibc_path_prefix + libc):
            self.set_glibc_path(libc)
            self.libc_version = libc
            self.libc = ELF(self.libc_path)
        else:
            self.get_libc_version(libc)
            self.libc_path = os.path.realpath(libc)
        
        if ld is not None:
            if not os.path.exists(ld):
                log.warning("ld: %s not exists..."%ld)
                self.set_ld_path(self.libc_version)
            else:
                self.ld_path = os.path.realpath(ld)
        else:
            self.set_ld_path(self.libc_version)
            
        self.build_info(env)

    def build_info(self, env):
        if not os.path.exists(self.ld_path):
            log.error("the ld %s is not exist, you can't use debug mode\n"
                      "please see the installation manual"%self.ld_path)
            exit(0)
        if not os.path.exists(self.libc_path):
            log.error("the libc %s is not exist, you can't use debug mode\n"
                      "please see the installation manual"%self.libc_path)
            exit(0)
        self.env=env
        if "LD_PRELOAD" in self.env:
            self.env["LD_PRELOAD"] = self.env["LD_PRELOAD"] +" "+ self.libc_path
        else:
            self.env["LD_PRELOAD"] = self.libc_path


    def run_init(self):
        shutil.copyfile(self.pwn_name, self.pwn_path)
        log.info("copy from %s to %s." % (self.pwn_name, self.pwn_path))
        sleep(0.2)
        os.chmod(self.pwn_path, 0o770)

        arch_path = "x86_64-linux-gnu" if self.arch == "amd64" else "i386-linux-gnu"
        usr_arch_path = "/usr/lib/x86_64-linux-gnu/" if self.arch == "amd64" else "/usr/lib32/"
        cmd = 'patchelf --set-rpath '
        for i in self.addso:
            cmd += i + ":"
        cmd += self.glibc_path_prefix + self.libc_version + "/lib/:/lib/" \
              + arch_path + ':' + usr_arch_path + ' ' + self.pwn_path
        log.info("run: " + cmd)
        os.system(cmd)
        cmd = 'patchelf --set-interpreter ' + self.ld_path + ' ' + self.pwn_path
        log.info("run: " + cmd)
        os.system(cmd)
        sleep(0.2)


    def parseDebug(self, debugstr):
        addresses = []
        command = []
        if debugstr is not None:
            assert isinstance(debugstr, list)
            for stri in debugstr:
                num = getNum(stri)
                if num:
                    addresses.append(num)
                else:
                    command.append(stri)
        return addresses, command

    def run_debug(self, scripts=None, fork_follow="child"):
        if self.libc_path is None: self.set_libc()
        self.run_init()
        self.process = process([self.pwn_path] + self.args, env=self.env)
        sleep(0.2)
        self.membp = membp(self.process)
        if self.membp.empty:
            log.warn("set breakpoint fail...")
        else:
            addresses, command = self.parseDebug(scripts)
            self.membp.breakpoint(addresses, fork_follow, command)
        return self.process

    def run_gdb(self, scripts=None, fork_follow="child"):
        if self.libc_path is None: self.set_libc()
        self.run_init()
        addresses, command = self.parseDebug(scripts)
        gdbscripts = "set follow-fork-mode %s\n" % fork_follow
        if len(command) == 0 and (self.elf.pie or (not self.elf.pie and len(addresses) == 0)):
            command = ["b main"]
        gdbscripts += "\n".join(command)
        if len(addresses) > 0:
            if self.elf.pie:
                log.warn("can't set breakpoint, elf.pie is True.")
            else:
                gdbscripts += "\n" + "\n".join(["b *"+hex(i) for i in addresses])
        if self.libc_path.startswith("/glibc/"):
            self.process = gdb.debug([self.pwn_path] + self.args, gdbscript=gdbscripts)
        else:
            self.process = gdb.debug([self.pwn_path] + self.args, gdbscript=gdbscripts, env=self.env)
        return self.process

    def run_local(self):
        if self.libc_path is None: self.set_libc()
        self.run_init()
        self.process=process([self.pwn_path] + self.args,env=self.env)
        self.membp = membp(self.process)
        return self.process


    def debug(self, scripts, fork_follow="child"):
        if self.membp.empty or self.process is None:
            log.warn("debug wrong! please run_local first!!!")
            return
        addresses, command = self.parseDebug(scripts)
        self.membp.breakpoint(addresses, fork_follow, command)


    def run_remote(self,host,port):
        if self.pwn_name:
            self.elf=ELF(self.pwn_name)
        if self.libc_path is None:
            self.set_libc()
        self.libc = ELF(self.libc_path)
        self.remote=remote(host, port)
        return self.remote


    def ret2dl_resolve(self):
        self.ret2dl_resolve=ret2dl_resolve(self)
        return self.ret2dl_resolve

     
    def fmtstr_payload(self,offset, writes, write_size='byte',numbwritten=0):
        return fmtstr.fmtstr_payload(offset,writes,write_size,numbwritten)

    def fmtstr_hn_complete(self,offset,write_payload):
        return fmtstr.fmtstr_hn_complete(offset,write_payload)

    
    def fmtstr_hn_payload(self,offset,write_payload):
        return fmtstr.fmtstr_hn_payload(offset,write_payload)



