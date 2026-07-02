"""Version-aware technology fingerprint database.

Maps technologies to version extraction patterns, lifecycle data,
and EOL/outdated status thresholds.
"""

from dataclasses import dataclass, field


@dataclass
class TechFingerprint:
    name: str
    category: str
    version_patterns: list[tuple[str, str]]  # (regex_with_group, source_description)
    eol_threshold: tuple[int, int] | None = None  # (major, minor) before which is EOL
    outdated_threshold: tuple[int, int] | None = None  # (major, minor) before which is outdated
    known_vulnerable_versions: list[str] = field(default_factory=list)
    cpe: str = ""


VERSION_DB: dict[str, TechFingerprint] = {
    "nginx": TechFingerprint(
        name="nginx",
        category="web_server",
        version_patterns=[
            (r"nginx/(\d+\.\d+\.\d+)", "Server header"),
        ],
        eol_threshold=(1, 18),
        outdated_threshold=(1, 20),
    ),
    "Apache": TechFingerprint(
        name="Apache HTTP Server",
        category="web_server",
        version_patterns=[
            (r"Apache(?:/(\d+\.\d+(?:\.\d+)?))?", "Server header"),
        ],
        eol_threshold=(2, 2),
        outdated_threshold=(2, 4),
    ),
    "IIS": TechFingerprint(
        name="IIS",
        category="web_server",
        version_patterns=[
            (r"IIS(?:/(\d+\.\d+))?", "Server header"),
        ],
        outdated_threshold=(10, 0),
    ),
    "Node.js": TechFingerprint(
        name="Node.js",
        category="runtime",
        version_patterns=[
            (r"node(?:\.js)?(?:/(\d+\.\d+\.\d+))?", "Server/X-Powered-By header"),
        ],
        eol_threshold=(16, 0),
        outdated_threshold=(18, 0),
    ),
    "Express": TechFingerprint(
        name="Express",
        category="framework",
        version_patterns=[
            (r"express(?:/(\d+\.\d+\.\d+))?", "X-Powered-By header"),
        ],
        outdated_threshold=(4, 16),
    ),
    "React": TechFingerprint(
        name="React",
        category="javascript_framework",
        version_patterns=[
            (r"react@?(\d+\.\d+\.\d+)", "Script URL / package.json"),
            (r"React v?(\d+\.\d+\.\d+)", "Inline JS / comment"),
        ],
        outdated_threshold=(17, 0),
    ),
    "Angular": TechFingerprint(
        name="Angular",
        category="javascript_framework",
        version_patterns=[
            (r"angular@?(\d+\.\d+\.\d+)", "Script URL"),
            (r"ng-version=\"(\d+\.\d+\.\d+)\"", "HTML attribute"),
        ],
        eol_threshold=(2, 0),
        outdated_threshold=(12, 0),
    ),
    "Vue.js": TechFingerprint(
        name="Vue.js",
        category="javascript_framework",
        version_patterns=[
            (r"vue@?(\d+\.\d+\.\d+)", "Script URL"),
            (r"Vue\.js v?(\d+\.\d+\.\d+)", "Inline JS"),
        ],
        eol_threshold=(2, 0),
        outdated_threshold=(3, 0),
    ),
    "Next.js": TechFingerprint(
        name="Next.js",
        category="javascript_framework",
        version_patterns=[
            (r"_next/static/chunks/(\d+\.\d+\.\d+)", "Build artifact"),
            (r"next@?(\d+\.\d+\.\d+)", "Script URL"),
        ],
        outdated_threshold=(12, 0),
    ),
    "Django": TechFingerprint(
        name="Django",
        category="framework",
        version_patterns=[
            (r"django/(\d+\.\d+(?:\.\d+)?)", "X-Powered-By header"),
        ],
        eol_threshold=(2, 2),
        outdated_threshold=(3, 2),
    ),
    "Flask": TechFingerprint(
        name="Flask",
        category="framework",
        version_patterns=[
            (r"flask/(\d+\.\d+(?:\.\d+)?)", "X-Powered-By header"),
        ],
        outdated_threshold=(2, 0),
    ),
    "Laravel": TechFingerprint(
        name="Laravel",
        category="framework",
        version_patterns=[
            (r"laravel(?:/(\d+\.\d+(?:\.\d+)?))?", "X-Powered-By header / cookie"),
        ],
        eol_threshold=(6, 0),
        outdated_threshold=(8, 0),
    ),
    "PHP": TechFingerprint(
        name="PHP",
        category="runtime",
        version_patterns=[
            (r"PHP(?:/(\d+\.\d+(?:\.\d+)?))?", "X-Powered-By header"),
        ],
        eol_threshold=(7, 4),
        outdated_threshold=(8, 0),
    ),
    "jQuery": TechFingerprint(
        name="jQuery",
        category="javascript_library",
        version_patterns=[
            (r"jquery[.-](\d+\.\d+\.\d+)", "Script filename"),
            (r"jQuery v?(\d+\.\d+\.\d+)", "Inline JS"),
        ],
        eol_threshold=(1, 12),
        outdated_threshold=(3, 0),
    ),
    "Bootstrap": TechFingerprint(
        name="Bootstrap",
        category="css_framework",
        version_patterns=[
            (r"bootstrap[.-](\d+\.\d+\.\d+)", "Script filename"),
            (r"Bootstrap v?(\d+\.\d+\.\d+)", "Inline CSS/JS"),
        ],
        eol_threshold=(3, 4),
        outdated_threshold=(4, 0),
    ),
    "WordPress": TechFingerprint(
        name="WordPress",
        category="cms",
        version_patterns=[
            (r"ver=(\d+\.\d+(?:\.\d+)?)", "URL query parameter / meta tag"),
            (r"WordPress(?:/(\d+\.\d+(?:\.\d+)?))?", "X-Powered-By header"),
        ],
        eol_threshold=(4, 0),
        outdated_threshold=(5, 0),
    ),
    "Drupal": TechFingerprint(
        name="Drupal",
        category="cms",
        version_patterns=[
            (r"Drupal(?:/(\d+\.\d+(?:\.\d+)?))?", "X-Powered-By / generator tag"),
            (r"Drupal (\d+\.\d+)", "Meta generator"),
        ],
        eol_threshold=(7, 0),
        outdated_threshold=(9, 0),
    ),
}


def get_fingerprint(tech_name: str) -> TechFingerprint | None:
    return VERSION_DB.get(tech_name)


def evaluate_version(tech_name: str, version_str: str) -> dict:
    """Evaluate a version against known lifecycle data.

    Returns a dict with keys: status (str), reason (str).
    """
    fp = get_fingerprint(tech_name)
    if not fp:
        return {"status": "unknown", "reason": "No lifecycle data available"}

    try:
        parts = version_str.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return {"status": "unknown", "reason": f"Unparseable version: {version_str}"}

    if version_str in fp.known_vulnerable_versions:
        return {"status": "known_vulnerable", "reason": f"{tech_name} {version_str} has known vulnerabilities"}

    if fp.eol_threshold:
        eol_major, eol_minor = fp.eol_threshold
        if major < eol_major or (major == eol_major and minor < eol_minor):
            return {"status": "end_of_life", "reason": f"{tech_name} {version_str} is end-of-life"}

    if fp.outdated_threshold:
        outdated_major, outdated_minor = fp.outdated_threshold
        if major < outdated_major or (major == outdated_major and minor < outdated_minor):
            return {"status": "outdated", "reason": f"{tech_name} {version_str} is outdated, latest recommended"}

    return {"status": "supported", "reason": f"{tech_name} {version_str} is currently supported"}
