from pathlib import Path
import toml
import click

DEFAULT_CONFIG = {
    "exclude": [
        ".venv",
        "venv",
        ".git",
        "__pycache__",
        "build",
        "dist",
        "*.egg-info",
    ],
    "severity": "LOW",
}

def load_config(config_path: Path) -> dict:
    """Loads configuration from a TOML file or returns defaults."""
    if config_path and config_path.exists():
        try:
            with config_path.open('r') as f:
                user_config = toml.load(f).get('tool', {}).get('pyspector', {})
                # Merge user config into defaults
                config = DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
        except Exception as e:
            click.echo(click.style(f"Warning: Could not parse config file '{config_path}'. Using defaults. Error: {e}", fg="yellow"))
    return DEFAULT_CONFIG

def get_default_rules() -> str:
    """Loads the built-in TOML rules file."""
    # Note: The path is relative to the project root, not the src directory
    rules_path = Path.cwd() / "pyspector_core" / "rules" / "built-in-rules.toml"
    if not rules_path.exists():
        raise FileNotFoundError(f"Built-in rules file not found at {rules_path}!")
    return rules_path.read_text()