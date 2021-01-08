import bisect
import collections
from typing import Union

import gdb as gdb

MapRegion = collections.namedtuple('MapRegion', 'start end size offset name')


class ProcMap:

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[MapRegion] = []
        self.keys = []

    def rebuild_map(self):
        lines: str = gdb.execute("info proc map", to_string=True)
        res = []
        for line in lines.splitlines():
            sline = line.strip()
            # print(f"L: {sline}")
            if sline.startswith("0x"):
                blocks = list(filter(lambda x: len(x) > 0, sline.split(" ")))
                # print(f"LB: {blocks}")
                res.append(MapRegion(start=int(blocks[0], 16), end=int(blocks[1], 16), size=int(blocks[2], 16),
                                     offset=int(blocks[3], 16), name=blocks[4] if len(blocks) == 5 else "Unnamed"))
        self.entries = res
        self.keys = [entry.start for entry in res]

    def get_record_at(self, address) -> Union[None, MapRegion]:
        index = bisect.bisect_left(self.keys, address)
        if 0 <= index < len(self.entries):
            entry = self.entries[index]
            if address <= entry.end:
                return entry
        return None

    def get_entry_for(self, name, offset):
        per_lib = filter(lambda entry: name in entry.name, self.entries)
        for ent in per_lib:
            if ent.offset <= offset < ent.offset + ent.size:
                return ent
        return None

