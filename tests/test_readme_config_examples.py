import re
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.config_file import CONFIG_SCHEMA_VERSION, load_config
from scylla_vms.desired import (
    ClusterSpec,
    NetworkMode,
    StorageBackend,
    compile_new_cluster_spec,
)

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
_CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _example(name: str) -> str:
    marker = re.compile(
        rf"<!-- config-example:{re.escape(name)}:start -->\n"
        r"```toml\n(?P<toml>.*?)```\n"
        rf"<!-- config-example:{re.escape(name)}:end -->",
        re.DOTALL,
    )
    matches = list(marker.finditer(_readme()))
    assert len(matches) == 1
    return matches[0].group("toml")


@pytest.mark.parametrize(
    ("name", "cluster_name", "zone_count", "jump_count", "network", "storage"),
    [
        (
            "minimal",
            "example-minimal",
            1,
            0,
            NetworkMode.CREATE,
            StorageBackend.BLOCK_VOLUME,
        ),
        (
            "complete",
            "example-multizone",
            3,
            2,
            NetworkMode.EXISTING,
            StorageBackend.AUTO,
        ),
    ],
)
def test_readme_toml_examples_load_and_compile_exactly(
    tmp_path: Path,
    name: str,
    cluster_name: str,
    zone_count: int,
    jump_count: int,
    network: NetworkMode,
    storage: StorageBackend,
) -> None:
    documented = _example(name)
    exact_config = tmp_path / f"{name}-exact.toml"
    exact_config.write_text(documented, encoding="utf-8")
    exact_config.chmod(0o600)
    loaded = load_config(exact_config)
    assert loaded.values["cluster_name"] == cluster_name
    assert CONFIG_SCHEMA_VERSION in documented

    # The documented path is intentionally fake; only the file-existence probe
    # is faked so the exact README bytes pass through the real loader and parser.
    with patch.object(Path, "is_file", return_value=True):
        request = parse_operation_request(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--config",
                str(exact_config),
                "deploy",
                "--dry-run",
                "--oci-auth-mode",
                "instance-principal",
            ],
            environ={},
        )
    configured_zones = request.option("zone").value
    assert isinstance(configured_zones, tuple)
    canonical_zones = {str(zone): str(zone) for zone in configured_zones}
    spec = compile_new_cluster_spec(
        request,
        cluster_uuid=_CLUSTER_UUID,
        canonical_zone_ids=canonical_zones,
    )

    assert spec.cluster_name == cluster_name
    assert len(spec.zones) == zone_count
    assert spec.services[2].count == jump_count
    assert spec.network.mode is network
    assert spec.storage[0].requested_backend is storage
    assert ClusterSpec.from_object(spec.to_object()) == spec
    assert not (tmp_path / "state").exists()


def test_readme_config_examples_and_commands_contain_no_secret_material() -> None:
    readme = _readme()
    for name in ("minimal", "complete"):
        example = _example(name).lower()
        assert "password" not in example
        assert "private_key" not in example
        assert "token" not in example
        assert "-----begin" not in example
    assert "--config /opt/deploy-scylla-vms/cluster.toml" in readme
    assert "DEPLOY_SCYLLA_VMS_CONFIG=/opt/deploy-scylla-vms/cluster.toml" in readme


def test_readme_fake_only_command_excludes_external_tool_installations() -> None:
    assert (
        'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PATH="/usr/bin:/bin" '
        ".venv/bin/python -m pytest -q"
    ) in _readme()


def test_readme_h2_table_of_contents_matches_headings() -> None:
    readme = _readme()
    toc_section = readme.split("## Table of contents\n", 1)[1].split("\n## ", 1)[0]
    links = re.findall(r"^- \[[^\]]+\]\(#([^)]+)\)$", toc_section, re.MULTILINE)
    headings = re.findall(r"^## (?!Table of contents$)(.+)$", readme, re.MULTILINE)
    anchors = [
        re.sub(r"-+", "-", re.sub(r"[^a-z0-9 -]", "", heading.lower())).replace(
            " ", "-"
        )
        for heading in headings
    ]
    assert links == anchors
