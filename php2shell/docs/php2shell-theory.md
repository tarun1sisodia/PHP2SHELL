# php2shell Theory

## Overview

php2shell is an exploit for two related PHP vulnerabilities:
- **CVE-2026-109618**: OOM/longjmp path to RCE
- **CVE-2026-109619**: UAF (Use-After-Free) path to RCE

Both vulnerabilities affect PHP's session upload progress feature and can lead to remote code execution under specific conditions.

## The Exploit Chain

### Step 1: Access Session Upload Progress

PHP's `session.upload_progress.enabled` directive allows tracking file uploads by storing progress information in the session. When enabled, PHP creates a special session key (`PHP_SESSION_UPLOAD_PROGRESS`) that contains the upload progress data.

### Step 2: Free the Session Data

The vulnerability occurs when:
1. A request with `session.upload_progress.enabled=On` is processed
2. The request body is large enough to trigger memory pressure
3. The request hits `memory_limit` during parsing

At this point, PHP's `zval` (Zend value) structures are freed but not properly cleaned up.

### Step 3: Trigger the UAF/OOM

The freed `zval` structures can be reallocated with controlled data through:
- **OOM path**: Send a request that exactly hits `memory_limit` mid-parse
- **UAF path**: Spray the heap with controlled data to reallocate the freed chunk

### Step 4: Poison the Session

The session poison payload is injected via the multipart form data:
```
--boundary
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<session_id><payload>
--boundary
Content-Disposition: form-data; name="file"; filename="file.txt"
Content-Type: text/plain

<filler data>
--boundary--
```

### Step 5: Trigger Include()

The final step is to trigger an `include()` or `require()` call that loads the poisoned session file. Common sinks:
- WordPress `index.php?page=<lfi>`
- Custom PHP applications with dynamic includes
- Any PHP file that includes user-controlled input

## Precondition Requirements

For the exploit to work, the following must be true:

1. **PHP Version**: The target must run a vulnerable PHP version:
   - PHP 5.x, 7.x (all versions)
   - PHP 8.0.x, 8.1.x (all versions)
   - PHP 8.2.x < 8.2.35
   - PHP 8.3.x < 8.3.36
   - PHP 8.4.x < 8.4.27
   - PHP 8.5.x < 8.5.12

2. **session.upload_progress.enabled**: Must be `On` (default is `On`)

3. **session.upload_progress.min_freq**: Must allow the upload to complete (default is `0.1`)

4. **memory_limit**: Must be finite and reachable (not `-1`/unlimited)

5. **include() sink**: There must be a PHP file that includes user-controlled input

## Memory Calculation

The heap spray size must match the freed `zval` bucket size:

- **Typical spray size**: 288 bytes
- **Spray count**: 149 fields (varies by PHP build)
- **Total spray size**: ~43KB

The exact values depend on:
- PHP version and build
- System architecture (32-bit vs 64-bit)
- Memory allocator (jemalloc vs malloc)

## CDN/Proxy Considerations

If a CDN or reverse proxy buffers POST bodies:
- The sub-second stall required for the exploit is lost
- The exploit will fail with "no command output"

**Solutions**:
1. Connect directly to origin IP with `--host-header`
2. Use `--chunked` for true chunked transfer
3. Try different spray counts (100-300 in steps of 10)

## Testing the Exploit

1. Run `recon.py` to verify preconditions
2. If `go: true`, run `php2shell.py` with appropriate parameters
3. Use `verify.py` to confirm command execution

## Safety Notes

- This exploit should only be used on systems you own or have explicit permission to test
- Unauthorized testing is illegal and unethical
- The exploit may cause denial of service if memory limits are not properly calculated
