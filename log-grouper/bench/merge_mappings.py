"""Merge mapping stores from parallel mapping agents (disjoint parsers) into the main store.

  python3 bench/merge_mappings.py <main store dir> <mapping store dir> [...]
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from loggrouper.parse.store import MappingStore

main = MappingStore(sys.argv[1])
by_parser = {m["parser_id"]: m for m in main.active()}
for src in sys.argv[2:]:
    st = MappingStore(src)
    for m in st.active():
        if m["parser_id"] in by_parser and by_parser[m["parser_id"]] is not m:
            main.items.remove(by_parser[m["parser_id"]])
        m = dict(m)
        m["id"] = main.next_id("m")
        main.items.append(m)
        by_parser[m["parser_id"]] = m
    main.data["rejected"] += st.data.get("rejected", [])
main.save()
print(f"{len(main.active())} active mappings in {sys.argv[1]}")
