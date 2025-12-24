# Password Strength Checker

A CLI tool to check password strength using entropy-based scoring and blacklist detection.

## Features

- **Entropy-based scoring**: Uses Shannon entropy to measure password randomness
- **Blacklist detection**: Checks against common leaked passwords
- **Character variety analysis**: Evaluates use of lowercase, uppercase, numbers, and special characters
- **Detailed feedback**: Provides actionable suggestions to improve password strength

## Installation

Clone this repository and navigate to the project directory:

```bash
git clone <repository-url>
cd Claude_test
```

Install dependencies (for development):

```bash
pip install -r requirements.txt
```

## Usage

Run the password checker using Python:

```bash
python3 -m password_checker
```

Or pass a password as an argument:

```bash
python3 -m password_checker "your_password_here"
```

## Testing

Run the test suite with pytest:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=password_checker --cov-report=term-missing
```

## Project Structure

```
password_checker/
├── __init__.py       # Package initialization
├── __main__.py       # Module entry point
├── cli.py            # CLI interface
└── checker.py        # Password strength logic (entropy, blacklist, scoring)

tests/
└── test_checker.py   # Unit tests for checker module
```
