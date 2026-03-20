# Ptmarker

Ptmarker scans a folder containing Cisco Packet Tracer `.pka` activity files,
extracts the score from each one, and saves all results to a CSV file.

---

## Prerequisites

- **Python 3.8 or higher** — no third-party packages required (uses the standard library only).
- **Cisco Packet Tracer is NOT required** — `.pka` files are parsed directly.

---

## Installation

1. Clone or download this repository.
2. No additional packages need to be installed.

```bash
git clone https://github.com/mylespeterson/Ptmarker.git
cd Ptmarker
```

---

## Usage

```bash
python main.py FOLDER [OUTPUT_CSV] [-v]
```

| Argument | Required | Description |
|---|---|---|
| `FOLDER` | Yes | Path to the folder containing `.pka` files (searched recursively). |
| `OUTPUT_CSV` | No | Destination CSV file (default: `results.csv`). |
| `-v` / `--verbose` | No | Enable verbose/debug logging. |

### Examples

```bash
# Scan a folder and write results to the default results.csv
python main.py /path/to/pka/folder

# Scan a folder and write results to a custom output file
python main.py /path/to/pka/folder grades.csv

# Enable verbose logging to see detailed parsing information
python main.py /path/to/pka/folder grades.csv --verbose
```

---

## Example CSV Output

```csv
filename,score,max_score,percentage,user_profile_name
lab1.pka,8,10,80.0%,John Doe
lab2.pka,15,20,75.0%,Jane Smith
lab3.pka,N/A,N/A,N/A,N/A
```

| Column | Description |
|---|---|
| `filename` | Name of the `.pka` file |
| `score` | The student's achieved score/points (or `N/A` if not found) |
| `max_score` | The maximum possible score/points (or `N/A` if not found) |
| `percentage` | Calculated as `(score / max_score) × 100`, formatted to one decimal place (or `N/A`) |
| `user_profile_name` | The student/user profile name stored in the file (or `N/A` if not found) |

---

## Project Structure

```
Ptmarker/
├── main.py          # CLI entry point
├── pka_parser.py    # Opens .pka archives, parses XML, extracts scores
├── csv_writer.py    # Writes results to CSV
├── requirements.txt # Python dependencies (none beyond stdlib)
└── README.md        # This file
```

---

## Notes on the `.pka` File Format

- `.pka` files are **ZIP-compressed archives** containing one or more XML files.
- The XML uses a schema defined by Cisco Packet Tracer.  Common elements include
  `<SCORING>`, `<SCORE>`, `<MAXSCORE>`, `<PERCENTAGE>`, and `<USERPROFILENAME>`.
- Ptmarker tries several common element/attribute name variants to handle
  differences between Packet Tracer versions.
- Files that cannot be read or do not contain scoring data are included in the CSV
  with `N/A` values, and a warning is printed to the console.

---

## Error Handling

| Situation | Behavior |
|---|---|
| Invalid folder path | Error message printed; exits with code 1 |
| No `.pka` files found | Informational message printed; no CSV written |
| Corrupted/unreadable `.pka` | Warning logged; file included with `N/A` values |
| Missing score data | Warning logged; file included with `N/A` values |