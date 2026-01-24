# Quick Testing Guide for Guardian CLI

> **TL;DR**: DevOps testing for people who lack testing experience

## Why Test?

Testing prevents:
- 💥 **Breaking existing features** when adding new ones
- 🐛 **Bugs in production** that users discover
- ⏰ **Wasted time** debugging issues that could've been caught early
- 😰 **Fear of changing code** because you don't know what will break

## Installation (One-Time Setup)

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Or use make
make install-dev
```

## Daily Development Workflow

### ✅ The Simple Loop

```bash
# 1. Make code changes
vim tools/my_tool.py

# 2. Run tests
make test-unit

# 3. Fix any failures
# 4. Repeat until tests pass
```

### ✅ Before Committing

```bash
# Run all quality checks
make lint          # Check code style
make test-unit     # Run tests
make format        # Auto-fix formatting

# Or combine them
make lint && make test-unit && git commit
```

## Common Commands (Copy-Paste Ready)

### Running Tests

```bash
# Run ALL unit tests (takes ~10 seconds)
make test-unit

# Run tests for specific tool
pytest tests/unit/test_tools/test_feroxbuster.py -v

# Run tests matching a pattern
pytest -k "exit_code" -v

# Run tests and show print statements
pytest tests/unit/ -s -v
```

### Coverage

```bash
# See what % of code is tested
make coverage

# Open coverage report in browser
make coverage-open
```

### Code Quality

```bash
# Check if code follows style guidelines
make lint

# Auto-fix most issues
make format
```

### Watch Mode (Advanced)

```bash
# Auto-run tests when files change
make test-watch
```

## Understanding Test Output

### ✅ Passing Test
```
tests/unit/test_tools/test_feroxbuster.py::TestFeroxbusterTool::test_exit_code_success PASSED [100%]
```

### ❌ Failing Test
```
tests/unit/test_tools/test_feroxbuster.py::TestFeroxbusterTool::test_exit_code_success FAILED [100%]

================================= FAILURES =================================
_____ TestFeroxbusterTool.test_exit_code_success _____

    def test_exit_code_success(self, tool):
>       assert tool.is_success_exit_code(0) == True
E       AssertionError: assert False == True

tests/unit/test_tools/test_feroxbuster.py:15: AssertionError
```

**What this means**:
- The test expected `is_success_exit_code(0)` to return `True`
- But it returned `False`
- Line 15 in test file is where it failed

## Writing Your First Test

### Step 1: Create Test File

```bash
# Create test file (name must start with test_)
touch tests/unit/test_tools/test_mytool.py
```

### Step 2: Copy This Template

```python
"""Test MyTool functionality"""
import pytest
from tools.mytool import MyTool

class TestMyTool:
    """Test suite for MyTool"""

    @pytest.fixture
    def tool(self, test_config):
        """Create tool instance for testing"""
        return MyTool(test_config)

    def test_basic_functionality(self, tool):
        """Test that tool does what it should"""
        result = tool.do_something()
        assert result == "expected_value"

    def test_exit_codes(self, tool):
        """Test exit code handling"""
        assert tool.is_success_exit_code(0) == True
        assert tool.is_success_exit_code(1) == False
```

### Step 3: Run Your Test

```bash
pytest tests/unit/test_tools/test_mytool.py -v
```

### Step 4: Iterate Until It Passes

If test fails:
1. Read the error message (tells you what's wrong)
2. Fix your code or your test
3. Run test again
4. Repeat until it passes ✅

## Real Example: Testing Feroxbuster

```python
def test_exit_code_no_results(self, tool):
    """Test that exit code 2 (no results) is considered success"""
    assert tool.is_success_exit_code(2) == True
```

**What this tests**:
- When feroxbuster finds no results, it exits with code 2
- This is NOT a failure - it means the tool ran successfully
- We want to make sure our code treats exit code 2 as success

## Test-Driven Development (TDD) - The Pro Way

### The Cycle

```bash
# 1. Write test FIRST (it will fail - that's good!)
def test_new_feature(self, tool):
    assert tool.new_feature() == "expected"

# 2. Run test (watch it fail)
pytest tests/unit/test_mytool.py::test_new_feature -v
# FAILED ❌

# 3. Write MINIMAL code to make it pass
def new_feature(self):
    return "expected"

# 4. Run test again (watch it pass)
pytest tests/unit/test_mytool.py::test_new_feature -v
# PASSED ✅

# 5. Refactor (improve code while keeping test passing)
# 6. Commit!
```

### Why TDD?

- ✅ You **know** your code works (test proves it)
- ✅ You **design** better APIs (tests show how code will be used)
- ✅ You **document** behavior (tests are living documentation)
- ✅ You **prevent** regressions (old tests catch new bugs)

## CI/CD (Continuous Integration)

### What Happens Automatically

When you push code to GitHub:

```
┌─────────────────────────────────────┐
│ You push code to GitHub             │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│ GitHub Actions runs tests           │
│ ├─ Install dependencies             │
│ ├─ Run linters (ruff, black)        │
│ ├─ Run unit tests                   │
│ └─ Check code coverage              │
└────────────┬────────────────────────┘
             │
             ├─ ✅ All pass → Merge allowed
             └─ ❌ Any fail → Fix before merge
```

### Viewing CI Results

1. Go to your GitHub PR
2. Scroll to bottom - see "All checks have passed" ✅
3. Or see "Some checks failed" ❌
4. Click "Details" to see what failed

## Common Issues & Solutions

### Issue: "ModuleNotFoundError: No module named 'pytest'"

**Solution**: Install test dependencies
```bash
pip install -r requirements-dev.txt
```

### Issue: Tests fail with import errors

**Solution**: Install package in editable mode
```bash
pip install -e .
```

### Issue: "Collection failed" - pytest can't find tests

**Solution**: Test files must follow naming convention
- Files: `test_*.py` or `*_test.py`
- Classes: `Test*`
- Functions: `test_*`

### Issue: Async tests fail

**Solution**: Mark async tests properly
```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result == expected
```

## Best Practices (Keep It Simple)

### ✅ DO

1. **Test one thing per test**
   ```python
   def test_exit_code_zero_is_success(self, tool):
       assert tool.is_success_exit_code(0) == True

   def test_exit_code_one_is_failure(self, tool):
       assert tool.is_success_exit_code(1) == False
   ```

2. **Use descriptive names**
   - ✅ `test_exit_code_no_results_is_success`
   - ❌ `test_1`

3. **Keep tests fast**
   - Mock external dependencies (APIs, files, etc.)
   - Don't actually run security tools in unit tests

### ❌ DON'T

1. **Test implementation details**
   - Test behavior, not how it's implemented
   - Tests should pass if you refactor code

2. **Make tests depend on each other**
   - Each test should run independently
   - Don't rely on test execution order

3. **Skip tests**
   - Fix or delete, don't skip
   - Skipped tests are forgotten tests

## Measuring Success

### Coverage Goals

```bash
make coverage

# Look for this:
TOTAL    1234    456     37    12    68%
         ^^^^                         ^^^
      total lines                  coverage %
```

**Target**: 70%+ coverage

### What to Test

**Priority 1 (Must test)**:
- Exit code handling
- Error recovery
- Command generation
- Critical business logic

**Priority 2 (Should test)**:
- Output parsing
- Configuration handling
- Edge cases

**Priority 3 (Nice to test)**:
- Error messages
- Logging
- Utility functions

## Getting Help

1. **Read the full guide**: [TESTING_FRAMEWORK.md](TESTING_FRAMEWORK.md)
2. **Look at examples**: `tests/unit/test_tools/`
3. **Run with `-h`**: `pytest -h`

## Next Steps

Now that you understand testing:

1. ✅ Run `make test-unit` - see what passes
2. ✅ Pick a tool without tests - write your first test
3. ✅ Run `make coverage` - see what needs testing
4. ✅ Set up pre-commit hooks - automate quality checks
5. ✅ Watch tests run in CI - see the magic happen

**Remember**: Testing seems hard at first, but it saves you SO much time in the long run. Start small, test one thing, and build from there! 🚀
