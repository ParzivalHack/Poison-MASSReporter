import sys
from pathlib import Path

# Manually add the 'src' directory to Python's path
# This ensures the interpreter can find your 'pyspector' package
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Now that the path is correctly set up, we can import and run the CLI
from pyspector.cli import cli

if __name__ == "__main__":
    cli()