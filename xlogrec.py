import os.path
from typing import Union

import gdb as gdb

import sys
from os.path import dirname
sys.path.append(dirname(__file__))

from procMap import ProcMap, MapRegion

proc_map = ProcMap()


class Recording:
    def __init__(self) -> None:
        super().__init__()
        self.file = None
        self.meta_log_file = None
        self.has_annotation = set()
        self.auto = False
        self.autoLib = None
        self.meta_id = 0
        self.logged_libs = {}

    def start(self):
        pid = gdb.selected_inferior().pid
        self.file = open(f"xlog-{pid}.log", "a")
        self.meta_log_file = open(f"xlog-{pid}.json.log", "w")

    def finish(self):
        self.file.close()
        self.meta_log_file.close()
        self.meta_log_file = None
        self.file = None
        self.auto = False
        self.autoLib = None
        self.has_annotation = set()
        self.meta_id = 0

    def inc_meta_id(self):
        self.meta_id = self.meta_id + 1


recording: Recording = Recording()


def log(self, *args, sep=' '):
    print(self, *args, sep, end='\n', file=recording.file)
    print(self, *args, sep)


import json


def del_none(d):
    """
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.
    """
    # For Python 3, write `list(d.items())`; `d.items()` won’t work
    # For Python 2, write `d.items()`; `d.iteritems()` won’t work
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d  # For convenience


def log_meta(meta):
    json.dump(meta, recording.meta_log_file)
    recording.meta_log_file.write("\n")


def pc_to_offset(entry: MapRegion, pc: int):
    return pc - entry.start + entry.offset


def log_meta_message(address: Union[int, None], entry: Union[MapRegion, None], **kwargs):
    r = {"id": recording.meta_id}
    if entry:
        r["pos"] = pc_to_offset(entry, address)
        r["name"] = shorten_library_name(entry.name)
    elif address is not None:
        r["address"] = address

    log_meta(dict(r, **kwargs))


# rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip
# eflags


rline = [
    ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    ["rax", "rdx"],
    ["rsp", "rbp"],
    ["r10", "r11", "r12", "r13", "r14", "r15"],
    ["eflags"]
]


#  0	CF	Carry Flag: Set by arithmetic instructions which generate either a carry or borrow. Set when an operation generates a carry to or a borrow from a destination operand.
#  2	PF	Parity flag: Set by most CPU instructions if the least significant (aka the low-order bits) of the destination operand contain an even number of 1's.
#  4	AF	Auxiliary Carry Flag: Set if there is a carry or borrow involving bit 4 of EAX. Set when a CPU instruction generates a carry to or a borrow from the low-order 4 bits of an operand. This flag is used for binary coded decimal (BCD) arithmetic.
#  6	ZF	Zero Flag: Set by most instructions if the result an operation is binary zero.
#  7	SF	Sign Flag: Most operations set this bit the same as the most significant bit (aka high-order bit) of the result. 0 is positive, 1 is negative.
#  8	TF	Trap Flag: (sometimes named a Trace Flag.) Permits single stepping of programs. After executing a single instruction, the processor generates an internal exception 1. When Trap Flag is set by a program, the processor generates a single-step interrupt after each instruction. A debugging program can use this feature to execute a program one instruction at a time.
#  9	IF	Interrupt Enable Flag: when set, the processor recognizes external interrupts on the INTR pin. When set, interrupts are recognized and acted on as they are received. The bit can be cleared to turn off interrupt processing temporarily.
# 10	DF	Direction Flag: Set and cleared using the STD and CLD instructions. It is used in string processing. When set to 1, string operations process down from high addresses to low addresses. If cleared, string operations process up from low addresses to high addresses.
# 11	OF	Overflow Flag: Most arithmetic instructions set this bit, indicating that the result was too large to fit in the destination. When set, it indicates that the result of an operation is too large or too small to fit in the destination operand.
# 12-13	IOPL	Input/Output privilege level flags: Used in protected mode to generate four levels of security.
# 14	NT	Nested Task Flag: Used in protected mode. When set, it indicates that one system task has invoked another via a CALL Instruction, rather than a JMP.
# 16	RF	Resume Flag: Used by the debug registers DR6 and DR7. It enables you to turn off certain exceptions while debugging code.
# 17	VM

def check_flag(value: int, name: str, off: int):
    return name + " " if value & (0b1 << off) > 0 else "   "


def decode_eflags(value: int):
    r = "[ "
    r = r + check_flag(value, "CF", 0)
    r = r + check_flag(value, "PF", 2)
    r = r + check_flag(value, "AF", 4)
    r = r + check_flag(value, "ZF", 6)
    r = r + check_flag(value, "SF", 7)
    r = r + check_flag(value, "OF", 11)
    return r + "]"


def encode_reg(name: str, value: int):
    if name == "eflags":
        return name + "\t" + decode_eflags(value) + "\t"
    else:
        return name + "\t" + hex(value) + "\t"


def dump_reg(arch, frame):
    regs = {}
    for reg in arch.registers():
        regs[reg.name] = frame.read_register(reg)

    # RDI, RSI, RDX, RCX, R8, and R9
    line = ""
    for block in rline:
        line = line + "  "
        for reg_name in block:
            line = line + encode_reg(reg_name, regs[reg_name])
        line = line + "\n"
    return line


reg_dump_insn = tuple([i.lower() for i in [
    "call", "ret",
    "JA", "JAE", "JB", "JBE", "JC", "JE", "JG", "JGE", "JL", "JLE", "JNA", "JNAE",
    "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE", "JNL", "JNLE", "JNO", "JNP", "JNS",
    "JNZ", "JO", "JP", "JPE", "JPO", "JS", "JZ"
]])


class HandleAutoNext:
    def __init__(self, lib_entry) -> None:
        super().__init__()
        self.lib_entry = lib_entry

    def __call__(self, *args, **kwargs):
        if not self.lib_entry or recording.autoLib != self.lib_entry.name:
            log("fell out")
            gdb.execute("finish")
        else:
            gdb.execute("si")


def shorten_library_name(name: str):
    if name.startswith("/"):
        if name in recording.logged_libs:
            return recording.logged_libs[name]
        else:
            short = os.path.basename(name)
            log(f"library {name} aka '{short}'")
            log_meta_message(None, None, type="lib_loc", name=name, short=short)
            recording.logged_libs[name] = short
            return short
    return name


def handle_frame():

    frame = gdb.selected_frame()
    lib_entry = proc_map.get_record_at(frame.pc())
    arch = frame.architecture()
    pc = frame.pc()
    insn = arch.disassemble(frame.pc(), count=1)
    if lib_entry:
        log(f"{shorten_library_name(lib_entry.name)}+{hex(pc_to_offset(lib_entry, pc))}: {insn[0]['asm']}")
    else:
        log(f"{hex(frame.pc())}: {insn[0]['asm']}")
    insn_asm: str = insn[0]['asm'].strip()

    log_meta_message(pc, lib_entry, type="insn", insn=insn_asm)

    if insn_asm.startswith(reg_dump_insn):
        regs = dump_reg(arch, frame)
        log(regs)
        rvalues = {}
        for rl in rline:
            for r in rl:
                rvalues[r] = int(frame.read_register(r))
        log_meta_message(pc, lib_entry, type="regs", values=rvalues)

    if recording.auto:
        gdb.post_event(HandleAutoNext(lib_entry))


def stop_handler(event):
    recording.inc_meta_id()
    handle_frame()


def end_recording():
    gdb.events.stop.disconnect(stop_handler)
    log("Stopped recording")
    log_meta_message(address=None, entry=None, type="stop")
    recording.finish()


def start_recording():
    recording.start()
    log("Start recording")
    log_meta_message(address=None, entry=None, type="start")
    gdb.events.stop.connect(stop_handler)
    proc_map.rebuild_map()
    log_meta_message(address=None, entry=None, type="procmap", entires=proc_map.entries)
    recording.autoLib = proc_map.get_record_at(gdb.selected_frame().pc()).name
    handle_frame()


class XLogRecord(gdb.Command):
    """Record execution log"""

    def __init__(self):
        super(XLogRecord, self).__init__("xlogrecord", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if args[0] == "start":
            start_recording()
        elif args[0] == "stop":
            end_recording()
        elif args[0] == "auto":
            BP(gdb.selected_frame())
            start_recording()
            recording.auto = True


class BP(gdb.FinishBreakpoint):
    def stop(self):
        end_recording()
        return True

    def out_of_scope(self):
        end_recording()


XLogRecord()

