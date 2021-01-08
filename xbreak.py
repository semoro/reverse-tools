import gdb as gdb

import sys
from os.path import dirname
sys.path.append(dirname(__file__))

from procMap import ProcMap

proc_map = ProcMap()


class XBreakpointImpl(gdb.Breakpoint):
    def __init__(self, address: int) -> None:
        super().__init__(f"*{hex(address)}")

    def delete(self):
        super().delete()
        xbreak.breaks = filter(lambda wrapper: wrapper.bp != self, xbreak.breaks)


class XBreakWrapper:
    def __init__(self, lib: str, offset: int) -> None:
        super().__init__()
        self.lib = lib
        self.offset = offset
        self.resolved = False
        self.bp = None
        self.reenable = True

    def try_resolve(self):
        if self.resolved:
            return
        if not self.reenable:
            return
        entry = proc_map.get_entry_for(self.lib, self.offset)
        if entry:
            addr = entry.start + (self.offset - entry.offset)
            print(f"Matching entry at {entry}")
            print(f"Resolved {self.lib}+{hex(self.offset)} at {hex(addr)}")
            self.bp = XBreakpointImpl(addr)
            self.resolved = True

    def disable(self):
        if self.bp and self.bp.is_valid():
            self.reenable = self.bp.enabled
            self.bp.enabled = False
        self.resolved = False


class XBreak(gdb.Command):
    def __init__(self):
        super(XBreak, self).__init__("xbreak", gdb.COMMAND_USER)
        self.openbp = None
        self.breaks = []

    def update_pending(self):
        for br in self.breaks:
            br.try_resolve()

    def on_program_exit(self):
        for br in self.breaks:
            br.disable()

    def invoke(self, arg: str, from_tty):
        if arg == "clear":
            if self.openbp:
                self.openbp.delete()
            self.openbp = None
            old_breaks = self.breaks
            self.breaks = []
            for br in old_breaks:
                if br.bp:
                    br.bp.delete()
            return
        if not self.openbp:
            self.openbp = OpenBreak(spec="dlopen")
        lib, offset = arg.split("+")
        self.breaks.append(XBreakWrapper(lib, int(offset, 16)))


xbreak = XBreak()


class OpenBreak(gdb.Breakpoint):
    def stop(self):
        proc_map.rebuild_map()
        xbreak.update_pending()
