# PHP2Shell Bulk Scanner

This automation script reads websites from an Excel sheet, identifies PHP/WordPress sites, and runs the php2shell exploit against vulnerable targets.

## Features

- **Bulk scanning**: Process hundreds of websites from an Excel file
- **PHP detection**: Automatically identify PHP-based websites
- **WordPress detection**: Identify WordPress sites
- **Vulnerability checking**: Run recon.py to check preconditions
- **Exploitation**: Run php2shell.py against vulnerable targets
- **Threaded processing**: Configurable number of concurrent threads
- **Excel output**: Generate formatted results report

## Installation

```bash
# Make setup script executable
chmod +x setup-automate.sh

# Run setup
./setup-automate.sh

# Or manually install dependencies
pip install -r requirements-automate.txt
```

## Usage

### Basic Usage

```bash
python3 automate-php2shell.py --input sites.xlsx --output results.xlsx
```

### Advanced Usage

```bash
# With 10 threads
python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --threads 10

# Force mode (skip precondition checks)
python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --force

# CVE-2026-109618 OOM mode
python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --oom

# Verbose mode
python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --verbose
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input`, `-i` | Input Excel file with URLs | Required |
| `--output`, `-o` | Output Excel file | `results.xlsx` |
| `--threads`, `-t` | Number of concurrent threads | `5` |
| `--timeout` | Request timeout in seconds | `30` |
| `--force` | Skip precondition checks | `False` |
| `--oom` | Exploit CVE-2026-109618 via OOM | `False` |
| `--path` | Path to include() sink | `/index.php` |
| `--lfi` | LFI payload | `/index.php` |
| `--param` | LFI parameter name | `page` |
| `--cmd` | Command to execute | `id` |
| `--chunked` | Use chunked transfer encoding | `False` |
| `--verbose` | Show verbose output | `False` |

## Excel Input Format

Create an Excel file with URLs in a column named `URL`:

| URL |
|-----|
| https://example.com |
| https://example.org |
| https://example.net |

Or use any column name (the script will auto-detect URL columns).

## Output

The script generates:

1. **Excel Results** (`results.xlsx`): Formatted report with:
   - Site URL
   - PHP detection status
   - WordPress detection status
   - Vulnerability status
   - PHP version
   - Memory limit
   - Session upload progress status
   - Exploit success status
   - Command output (truncated)
   - Error messages

2. **JSON Results** (`results/exploit/*.json`): Full exploit results for each site

3. **Summary** (`results/summary.json`): Statistics

## Excel Output Format

The output Excel file includes color-coded cells:
- **Green**: PHP detected / Vulnerable / Exploit successful
- **Yellow**: WordPress detected

## Example Workflow

1. **Prepare your site list** in an Excel file:
   ```excel
   URL
   https://example.com
   https://example.org
   https://example.net
   ```

2. **Run the scanner**:
   ```bash
   python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --threads 10
   ```

3. **Review results** in `results.xlsx`

4. **Check detailed results** in `results/exploit/` for successful exploits

## Requirements

- Python 3.8+
- openpyxl
- pandas
- requests

Install with:
```bash
pip install -r requirements-automate.txt
```

## Notes

- The script uses threading for concurrent processing
- Each thread runs recon.py and php2shell.py as subprocesses
- Results are saved incrementally to prevent data loss
- Use `--force` mode if you want to skip precondition checks
- Use `--oom` mode to exploit CVE-2026-109618 (OOM path)

## Troubleshooting

**Error: "openpyxl not installed"**
```bash
pip install openpyxl pandas
```

**Error: "recon.py not found"**
Make sure you're running from the scripts directory or have the correct path to recon.py

**Slow scanning**
Increase the number of threads with `--threads N` (be careful not to overload the target)

**Connection timeouts**
Increase the timeout with `--timeout N` (default: 30 seconds)
