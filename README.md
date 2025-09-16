# MW5 Save → JSON

A lite, heuristic tool to peek inside MechWarrior 5: Mercenaries save files (.sav) and dump a best-effort JSON view. It’s intended to help you locate values of interest in otherwise opaque binary data.

Typical things you might search for in the output:
- `AvailableCBills`
- `StartingDateTicks` (start date of the campaign or career)
- `ExecutionDate` (next payment due date, found after a path that looks like `/Game/Campaign/TimelineEvents/FinanceEvent/FinanceEvent.FinanceEvent_C`)
- `TotalTimeElapsed` (days elapsed in the game)
- Various flags, enums, Guids, and object paths

Note: This is not a full or authoritative parser. It trades completeness for simplicity and speed.

---

## What it does

- Scans the save file for recognizable UnrealEngine-ish property markers and nearby keys.
- Heuristically decodes common scalar types (int32/int64, float/double, boolean) and string-like data (paths, quoted text).
- Attempts to interpret .NET-style DateTime “ticks” and present a human-readable ISO timestamp where found.
- Outputs a JSON file alongside your .sav for convenient searching and inspection.

The JSON structure is a best-effort tree of keys and values; when keys repeat, you may see lists. Some sections may appear nested (arrays/maps/struct-like blocks), but the shape is not guaranteed to mirror the exact in-game object model.

---

## Limitations and caveats

- This is a rough viewer: some data types may not be decoded correctly.
- On large saves, some content may be missing in the output JSON due to recursion and list-size limits intended to prevent runaway processing.
- Keys are discovered heuristically; names may be missing, repeated, or partially recovered.
- Numeric fields may occasionally be misread depending on local context.
- Arrays and maps are approximated; ordering and grouping are not guaranteed.

If you can’t find a value, try searching for multiple related keys or alternate spellings.

---

## Requirements

- [Python 3.12+](https://www.python.org/) (earlier versions may work but haven't been tested)
- No third-party dependencies (standard library only).
- A virtual environment is recommended for isolation but not required.

---

## Usage

1. Optional: create and activate a virtual environment.
   - Windows (PowerShell)
     - `python -m venv .venv`
     - `.\.venv\Scripts\Activate.ps1`
   - macOS/Linux (bash/zsh)
     - `python3 -m venv .venv`
     - `source .venv/bin/activate`

2. Run the script and provide the path to your .sav when prompted:
   - Windows
     - `python mw5_save_to_json.py`
   - macOS/Linux
     - `python3 mw5_save_to_json.py`

3. The tool writes a .json file next to your .sav with the same base name.

Example:
- Input: C:\Users\You\Saved\Save_001.sav
- Output: C:\Users\You\Saved\Save_001.json

Open the JSON in your favorite text editor and search for keys like `AvailableCBills`, `StartingDateTicks`, `ExecutionDate`, or `TotalTimeElapsed`.

---

## Tips for searching

- Monetary: `AvailableCBills`
- Campaign start time: `StartingDateTicks`
- Next payment due date: `ExecutionDate`, found after a path that looks like `/Game/Campaign/TimelineEvents/FinanceEvent/FinanceEvent.FinanceEvent_C`
- Days elapsed in the game: `TotalTimeElapsed`
- General time fields: any key with “Ticks” often indicates a .NET tick count (100 ns) since January 1, 0001

---

## Editing your save (advanced)

If you want to make direct changes to the save file, consider using a hex editor (for example, [HxD](https://mh-nexus.de/en/hxd/) on Windows). Tips:

- Always make a backup of your save before editing.
- Use the JSON output to locate nearby keys/values, then search for those byte patterns in the .sav.
- Be mindful of endianness and data sizes; modifying lengths or structure can corrupt the file.
- Make small changes and test incrementally.
- There is a nice [video on YouTube](https://www.youtube.com/watch?v=eAZJBbbgN0E) that can show you how to edit MW5 save files with a hex editor.

Editing is entirely at your own risk.

---

## Troubleshooting

- JSON is missing large chunks:
  - Very large or deeply nested sections may be truncated by built-in depth and list-size limits. Try searching the original save file using a hex editor.
- Values look wrong:
  - Heuristics can misinterpret ambiguous byte patterns. Cross-check with multiple occurrences or related fields.
- Nothing useful appears:
  - Ensure you pointed to a valid MW5 .sav. Try a different save or search for broader keywords in the JSON.

---

## Safety and backups

This script reads your save and writes a separate JSON file. It does not modify the original save. Still, it’s good practice to back up your saves before experimentation.
