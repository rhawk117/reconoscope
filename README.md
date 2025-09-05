# Reconoscope

An OSINT CLI tool with support for domain, account probing, ip geolocation, phone number lookup,
website static client side analysis and more.

## About
This project is under active development, but should be usable in it's current state, reach out
if you have any questions or find any bugs. Once, I have the chance to remove the cursed dataclass
CLI args and normalize async, this should be one of the fastest tools of it's kind in python. The
account probing module is insanely fast due to it's use of multiprocessing and async.


## Installation


### UV Setup

- Build the project:
  ```bash
  uv build
  ```
- Install the project:
  ```bash
  uv pip install -e .
  ```
- Test it works by running the command:
  ```bash
  uv run reconoscope --help
  ```

### Venv Setup

- Create a virtual environment:
  ```bash
  python -m venv .venv
  ```
- Activate the virtual environment:
  ```bash
  source .venv/bin/activate  # On Unix or MacOS
  .venv\Scripts\activate     # On Windows
  ```
- Install the project:
  ```bash
  pip install -e .
  ```
- Test it works by running the command:
  ```bash
  python reconoscope --help
  ```


## TODO


- File analyzer module
- More robust website static analysis including client side
javascript package detection
- CI/CD pipeline
- Initial release
- Refactor to not use cursed dataclass setup for cli args
- Better docs