"""Integrity-checked packaged Ansible content and runtime configuration staging."""

import hashlib
import importlib.resources
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from scylla_vms.ansible.registry import get_playbook
from scylla_vms.errors import StatePersistenceError, UnsafePathError
from scylla_vms.state import StatePaths, validate_state_directory, validate_state_file

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

ANSIBLE_SOURCE_VERSION = "ansible-content/v1"
_MAXIMUM_FILE_BYTES = 512 * 1024
_SOURCE_HASHES = {
    "ansible.cfg": "sha256:0ed8f5250c21ab37be8c3c5908d9f3619b54d4cf10f9eb82ee45b2e840a98be9",
    "playbooks/base-os.yml": "sha256:8bdec85032efba2c0499ae6e7c92a7ebaecc9bf63e96bd3c218ba31ef35e03ba",
    "playbooks/connectivity-check.yml": "sha256:53f34e3e360764b67218b637824c40d785eb6e9e7ab1307b5be9b78fc082f302",
    "playbooks/deploy-reboot.yml": "sha256:0c7adb9e53e4506d5db8053ecfd8a2b87044b070421442e73e698e3f6e7282cc",
    "playbooks/evidence-collect.yml": "sha256:20f2e2d32caf02f7b04e5a8006928f867b064fdc0ff616a4cd94c80cf11cac28",
    "playbooks/inventory-preflight.yml": "sha256:923492a9f8a9100dd15062fba36d6262930fe8c98d556bc12d7bd2e8f4a8a92d",
    "playbooks/jump-host-configure.yml": "sha256:feb0a5d798f4bb63ed6b4322f5b98373399024eb85fff815ad5a9d372c099852",
    "playbooks/manager-agent.yml": "sha256:736d979790bd1a55f2dcc69534185151826d20d769800ff933998cf32fc20710",
    "playbooks/manager-backend-local-install.yml": "sha256:eb2f889402d667cb9cbd84d4396aedbaa21df4cdc383c56c5a88e15003d9d28c",
    "playbooks/manager-backend-preflight.yml": "sha256:288424ac7266f68d8246dc850ea3f6d823a1c9819612eceeca107adab13e6dfd",
    "playbooks/manager-backend-storage-discover.yml": "sha256:94228356316924abcc24e22f20ad86dae53721e5fe4e290344410f12885a9227",
    "playbooks/manager-backend-storage-preflight.yml": "sha256:feb25aa1d516d4947a10052ec8ef76a6bddd23c1551b4b576bb675b6e20dc9d7",
    "playbooks/manager-backend-storage-prepare.yml": "sha256:46b99e0464e65b52fa1e2bc90849277721b046d428560d0a25f946660452a892",
    "playbooks/manager-server.yml": "sha256:348178bc4aee0133f760bde02ebd6a96434a0e6732051eb0524a391ce6ab8998",
    "playbooks/manager-tasks.yml": "sha256:1bff254d4f0ebf618319ece365ae7bbbcdb75204a1f7761a690014a8122cfef9",
    "playbooks/monitoring-agent.yml": "sha256:d79b718a56060a1055d974d9085a6b9ff2cefe89268dbb2ed86a65da7dc70dd7",
    "playbooks/monitoring-stack.yml": "sha256:d7da73772ccbe7bda89d391e2d31053018889302ade40cf6ac15ec8a024984f6",
    "playbooks/monitoring-targets.yml": "sha256:956ca9c2f0e4896faf791aba34cdc4ebc35fc03a5f45a4bae171be5b2ea1084d",
    "playbooks/os-upgrade-in-place.yml": "sha256:5177478b4f9a4423acbbf642b4d804741d08e0d25e3ba3991e49114bbf261cc6",
    "playbooks/os-upgrade-postcheck.yml": "sha256:9a9b523a41ce62af81907c165c39d82b12e496457ee4cf247e00ed7a04280847",
    "playbooks/os-upgrade-preflight.yml": "sha256:87136d6088ba402bb23ebe6b2022ebf35c85effc0ff1f6d1b383b92dea8d32c0",
    "playbooks/os-reprovision-prepare.yml": "sha256:f6769c6d570c642c31f4aa4f418aa4d3a45e35bd25bc46c491e461f193034ba6",
    "playbooks/routed-keyscan.yml": "sha256:593a492757fcc7750e8e56e5914a00af99e777f000c611c76bfb2e92d6e848d0",
    "playbooks/storage-discover.yml": "sha256:47736d5b63fafe258d9c1bd22b06e4d849576ca430d52ec6f65261c345b65e14",
    "playbooks/storage-postcheck.yml": "sha256:30ffd47ef9844fa8158292639582a3cd057e51a1641636559fa0db5d19986cae",
    "playbooks/storage-preflight.yml": "sha256:350588e41c56016bb30d7a2b8b873bebe46743bfa14989bf28df2562dbc3e911",
    "playbooks/storage-prepare.yml": "sha256:b97180fa3cbc94d73ebaa5232b2bc54342c68f5bcbde8ee5bf06b64227cd8adf",
    "playbooks/storage-retire.yml": "sha256:8233b4c63222da40e6a369ad7ccbd5b166e491a64fb34e77598c09ec03013548",
    "playbooks/scylla-bootstrap.yml": "sha256:f28e2b92bf2c4881b5816ca81d64d7e0022609ef5dace020def88672b4a0bf44",
    "playbooks/scylla-cleanup.yml": "sha256:3595d655d964c58194b6c6805a202e25c195a266e9dd90abcec5dfbe7e001b32",
    "playbooks/scylla-cluster-shutdown.yml": "sha256:d4060e458e8e9d93d5e33c5256a9d920ba7985ee6392d8e03b52cd925afcd0c9",
    "playbooks/scylla-configure.yml": "sha256:27dfdd7258245f524489912fea4919d5dcab8b71e76380cdfe11ab4830d97a5a",
    "playbooks/scylla-health.yml": "sha256:ee620f39d71c599dd93e20ca6de7c2ac6b07514f6028505a1db8685f7b2e3d01",
    "playbooks/scylla-install.yml": "sha256:553a359bd87e0d795742994ac67960bb09c98c851ce4845fbc97d145ed7329d9",
    "playbooks/scylla-remove-live.yml": "sha256:1750d6a41c65e6d2c2bddd6cefb8673abf7d19d7c889b6040150f55c75bf4d58",
    "playbooks/scylla-remove-dead.yml": "sha256:8f39b63efa7f00cad452c380a04416641a4810d41d7318c7195879dc6a6891ae",
    "playbooks/scylla-replace-dead.yml": "sha256:0de17199b952110640399728ce73aaa40b58e76dea67e90e3d6118b9f3a83cc6",
    "playbooks/scylla-repair.yml": "sha256:c9bdfa9379b91712937f4ff088baf9c59a31b0c9b0a83c67d6f16da640dfef98",
    "playbooks/service-converge.yml": "sha256:38e7ed7ae7e49131a2ab49fb494a0ea55539968a9651fd3d0db66e0dcad2e9b4",
    "requirements.yml": "sha256:78aa83e7b0041e3a490b565f46d6929a53395b513322c9f9c3eda4f30fcc321d",
    "playbooks/roles/base_os/tasks/Ubuntu.yml": "sha256:5fec0a7244b7fe5b393d6fd321918b46e0da5798e82d7ee80b4bfa3f43f1018d",
    "playbooks/roles/base_os/tasks/main.yml": "sha256:59f0165352748a12b1d2b2d980bcb8557ce7b71a5ad85ed903fd61124d135d08",
    "playbooks/roles/jump_host_configure/handlers/main.yml": "sha256:5f146c72bcef5345032211adf1a0a00c6b426889e649cefdc88e32f2ff2e5dc9",
    "playbooks/roles/jump_host_configure/library/jump_host_configure.py": "sha256:876eb9f8e8bf7492aaaee3dad61c94f225d6e090635d5ab5b3a78adbc3dfe230",
    "playbooks/roles/jump_host_configure/tasks/main.yml": "sha256:8a0032727466bc3db6fa1680cd862a5e5c82478ce32cff406e3db47cad440338",
    "playbooks/roles/manager_agent/files/scylladb-manager-3.12-key.provenance.yml": "sha256:740cd6f6a1369915a36fa3ae31f6bfca4f855dbfe87422255b045e0baf4f78c3",
    "playbooks/roles/manager_backend_local_install/files/manager-backend-local-install.provenance.yml": "sha256:3af64f365e7710525801964566de85ad2644ff8634f978588cfdd098727eecfb",
    "playbooks/roles/manager_backend_local_install/tasks/main.yml": "sha256:ec6bedc57a7304ceb76f4d6a3d6a63dc2ff6f14cbc300f61e2402d6029c18dc6",
    "playbooks/roles/manager_backend_preflight/files/manager-backend-preflight.provenance.yml": "sha256:9d458bdeb36e334dfb9d44f240fc8866e746b34358e960b72c6ee3a13b821457",
    "playbooks/roles/manager_backend_preflight/library/manager_backend_preflight.py": "sha256:adcd68748366093cd567eaf1bcaf2d2f80aba48828986f9f12ec08b7c78a1e63",
    "playbooks/roles/manager_backend_preflight/tasks/main.yml": "sha256:a8a8e6c704686d6d97203f10d9b6cd7735782e93e42ad49f93fa29f3dc0c2903",
    "playbooks/roles/manager_backend_storage_discover/files/manager-backend-storage-discover.provenance.yml": "sha256:453f9ba7cab82b87f1141cbdd078251ce1ab1b0b1c5f6f05e43391db68132cc9",
    "playbooks/roles/manager_backend_storage_discover/library/manager_backend_storage_discover.py": "sha256:008cfa796b30c425814f82e7bcc2b8c2c2d86902302ceea69c05ba7631c7d321",
    "playbooks/roles/manager_backend_storage_discover/tasks/main.yml": "sha256:27bff0d70d4731ccc9fe5c0e22f71467290331af1f681f7e476487d8c52fbfff",
    "playbooks/roles/manager_backend_storage_preflight/files/manager-backend-storage-preflight.provenance.yml": "sha256:85533450e9e5b4f2e5cd713de974cfba938ae13f81acf0e51d755e70769c2d1b",
    "playbooks/roles/manager_backend_storage_preflight/library/manager_backend_storage_preflight.py": "sha256:ca87f077ff7a4fcb1cba99f8fddf317ef54eecacd010ff409bc27b80a7699018",
    "playbooks/roles/manager_backend_storage_preflight/tasks/main.yml": "sha256:f1dbf94bd20e29b041c87475362edb4f3942d70b7f715317e01910bc2f16fe21",
    "playbooks/roles/manager_backend_storage_prepare/files/manager-backend-storage-prepare.provenance.yml": "sha256:bd20ae11d5a8b46662cd71a7ef6d584402ace74302eeece377dab00d186b9315",
    "playbooks/roles/manager_backend_storage_prepare/library/manager_backend_storage_prepare.py": "sha256:80fab0fceb88d984cf12ec8cafbc293d5d6f4a5f9efe0efce202a2cff658729d",
    "playbooks/roles/manager_backend_storage_prepare/tasks/main.yml": "sha256:e7de8d54e53079545f3ea1cdfe8142d4ee481290dbd21a6adef50100718b6bbf",
    "playbooks/roles/manager_server/files/scylladb-manager-3.12-key.provenance.yml": "sha256:47af0bd34e068305fabbe23741339539e3936ec8d093a9101784221a1bc7fe44",
    "playbooks/roles/manager_tasks/files/scylladb-manager-3.12-tasks.provenance.yml": "sha256:0fb8550b260c9adebe94e5fb9e944022c734334ea304c5e5d80064b878b8bfeb",
    "playbooks/roles/monitoring_agent/files/scylladb-2026-node-exporter.provenance.yml": "sha256:a17af77b11f5c3f4c7b9d170a8803186f33dab8b89f3cb02dd983c58e6a800f7",
    "playbooks/roles/monitoring_stack/files/scylla-monitoring-4.16.0.provenance.yml": "sha256:17d1ed30e8481aa2af73820304d1513d8d471952e9cb4bd1475062b29ddb405e",
    "playbooks/roles/monitoring_targets/files/scylla-monitoring-4.16.0-targets.provenance.yml": "sha256:a0b7e876fa6c2ac3fef830585b9bc356b4bb24afefa714b6ef3c40e4abad9520",
    "playbooks/roles/os_upgrade_in_place/files/os-upgrade-in-place.provenance.yml": "sha256:0709f866b7d421e87265671e3cb45214dc1b3e611adbf89609a4883c42569b49",
    "playbooks/roles/os_upgrade_postcheck/files/os-upgrade-postcheck.provenance.yml": "sha256:bc7e38f3ecdd4bb97a25f82e24c6312c232d442874497efc3823e7798a99af70",
    "playbooks/roles/os_upgrade_postcheck/library/os_upgrade_postcheck.py": "sha256:ed57d0df8d259d83523267ce331c20009ae97a7476781a081d3188c5eda8ed0f",
    "playbooks/roles/os_upgrade_postcheck/tasks/main.yml": "sha256:9a8877a2cc81d95c90969339628e7dd74fde250b0f9a53609be510a0a91298d0",
    "playbooks/roles/os_upgrade_preflight/files/os-upgrade-preflight.provenance.yml": "sha256:a3829aa7be89b0ee68a7ac199652ca104de40df51e024734399a482502a20851",
    "playbooks/roles/os_upgrade_preflight/library/os_upgrade_preflight.py": "sha256:ed3ed915106fb10925cc089aa19ae2d4e28f0be6a0e1062bc3040e649ade9b82",
    "playbooks/roles/os_upgrade_preflight/tasks/main.yml": "sha256:e92770ec2a8cef2deb699955ad4ddfca774ac0cbdce48334918e848682e3a631",
    "playbooks/roles/os_reprovision_prepare/files/os-reprovision-prepare.provenance.yml": "sha256:97ffc5787eef7ccc1f7d6761b5f156d1bccdbf5e065bba7000bbc041a29e68c8",
    "playbooks/roles/routed_keyscan/library/routed_keyscan.py": "sha256:8917c0c73efcf9abc2ef89349eabb003c3cf5cd8684d1f7b8cc88381bbad5d8e",
    "playbooks/roles/routed_keyscan/tasks/main.yml": "sha256:c3571842d115beda65fcf3df48254de3420be447634257acf2ef1977c90e2d40",
    "playbooks/roles/storage_discover/library/storage_discover.py": "sha256:b89301d0b5811942b16e54c2aae7bce200076e95c3c0eea9566980096ac74e66",
    "playbooks/roles/storage_discover/tasks/main.yml": "sha256:826e3cb40c99009f8f6dfc61e93ec51596ca83f031d048f1b928dfc66820d33f",
    "playbooks/roles/storage_postcheck/library/storage_postcheck.py": "sha256:e02c957989f635f53afc441ca04696ab81db5a314d45c516c7f65385bc76caec",
    "playbooks/roles/storage_postcheck/tasks/main.yml": "sha256:3e845baed8924484330393963fca2c5bec4acc629c28d16d893819efe26ecf78",
    "playbooks/roles/storage_preflight/tasks/main.yml": "sha256:2331af7a75c259326160447f0cd669e7fa41c76a940fa206bac99285a3775bf5",
    "playbooks/roles/storage_prepare/library/storage_prepare.py": "sha256:d31c86ca04c4b5dda6257f531e1d7b6b4b861f35271333bd044af6ea86ec4c76",
    "playbooks/roles/storage_prepare/tasks/main.yml": "sha256:13d4a5dde1b4d45fcfd033a782841a5c57c69ce2480685a458f8a2176bc448d0",
    "playbooks/roles/storage_retire/library/storage_retire.py": "sha256:b8ba1bacd1c0e3743feee1fa1c43ff46fddce41f4eeba6fa1b93817c70178dfb",
    "playbooks/roles/storage_retire/tasks/main.yml": "sha256:11add0d2db700ea528ce7ebc962da4184e428d0aac6bed379ee750586fc94422",
    "playbooks/roles/scylla_configure/tasks/main.yml": "sha256:d0f9271ab48226f6b52aea7344269a2fd3d86d41d9fa182f889d8cca9934f27d",
    "playbooks/roles/scylla_bootstrap/tasks/main.yml": "sha256:2fdacd5c565d4ef94c73925beeaffa9d1c3ce72509ed1c2ff64d293e215d3252",
    "playbooks/roles/scylla_cleanup/library/scylla_cleanup.py": "sha256:b809b9688c99b7fffbf65167384f59a5ff105f37eb7d4f0897ac52c3a84d45ae",
    "playbooks/roles/scylla_cleanup/tasks/main.yml": "sha256:5d24f6c8fb9a18ca7a6791dcd873569fa39c64d9fab77895a42b029162aab144",
    "playbooks/roles/scylla_cluster_shutdown/files/scylla-cluster-shutdown.provenance.yml": "sha256:120b466d19198f9403a6c03a75ef143a3ea49a89e35662b8fdc6ab8ff1e2d0ce",
    "playbooks/roles/scylla_cluster_shutdown/library/scylla_cluster_shutdown.py": "sha256:3f6bd785bf4fd44e29eeeaad796430c6abf88bccd2de14963b987697df6e812b",
    "playbooks/roles/scylla_cluster_shutdown/tasks/main.yml": "sha256:c8ab7b7b64883e3b3a10b034331f4b645cd1de76f30cae7cab4397b681796f26",
    "playbooks/roles/scylla_configure/templates/cassandra-rackdc.properties.j2": "sha256:89b5d3ffdd4f45e18cf6994e9f2193ea9542318abaf780b36b989406d15c9d13",
    "playbooks/roles/scylla_configure/templates/scylla.yaml.j2": "sha256:dd055358b90eab5d11dff405f99655bcd87f9d48bd8f33b2b4f9875251a998e3",
    "playbooks/roles/scylla_health/library/scylla_health.py": "sha256:ebd8fd92160e1985ccf9cd7d9929c26cb2f6c683c12e0584d8d100f1960e72d2",
    "playbooks/roles/scylla_health/tasks/main.yml": "sha256:f9aaaf056ec6a16422d145e20c3c5229f3976bbd2a4efa55a7a5a753d51c0617",
    "playbooks/roles/scylla_remove_live/library/scylla_remove_live.py": "sha256:a12a38f419ab1cb6354fe8ca95c9b348dabb69ee0659ccff298038a760199a03",
    "playbooks/roles/scylla_remove_live/tasks/main.yml": "sha256:114db6e935516138b64ae58810138ad4c7a092ebc3790d743b7d91b192b1a451",
    "playbooks/roles/scylla_remove_dead/library/scylla_remove_dead.py": "sha256:5e72ac1cb36deeb5bd114dbd8f454678a3c3a60083d2bf20f9f7cf41997e23f5",
    "playbooks/roles/scylla_remove_dead/tasks/main.yml": "sha256:9fc90f8e2a81c9856d14275649ee70dc608b9dd43b41903ba8f16d32516e33b2",
    "playbooks/roles/scylla_replace_dead/library/scylla_replace_dead.py": "sha256:a6d2f25933fa44f9ea561ec2d65b1d54fdb37219fff68f607bd336b39ff58f27",
    "playbooks/roles/scylla_replace_dead/tasks/main.yml": "sha256:9c02ce0ee1678d9fa80f84d1c4788d7eced13b6e708a6895a1463bb42effddf3",
    "playbooks/roles/scylla_repair/library/scylla_repair.py": "sha256:cb7c737ba621e2572cb79ddc1a3ad870eb4a5331306540911dec3e940ec9eea7",
    "playbooks/roles/scylla_repair/tasks/main.yml": "sha256:866ee3d711bf138bda66121013653f67ec732723bbfcfc37b3cefb33b20671c3",
    "playbooks/roles/service_converge/files/service-converge.provenance.yml": "sha256:5797e05719b2c832c91e0daffd03d43f9cf8b7998afc97c8664058af40c90139",
    "playbooks/roles/service_converge/library/service_converge.py": "sha256:b8d2dcc642e8b52473644afd05518481f5cc8b7862ae44590fe6c1deeb2e0926",
    "playbooks/roles/service_converge/tasks/main.yml": "sha256:c2b20d23582b8c38cbae6f12839697fbcdd77f5943568e98c1fb2a6718c9683c",
    "playbooks/roles/scylla_install/files/scylladb-2026.asc": "sha256:f2f1f4368a71820ea1f5e4e8900e59ddeec1e78cf98450f3ac84826c828ea417",
    "playbooks/roles/scylla_install/files/scylladb-2026-key.provenance.yml": "sha256:bd2e4519910a6524339d9494f1e3513ec1682c7600c76e42a06c47fb3a7c2ed3",
}
_CONFIG_TOKEN = {
    "@@INVENTORY@@": "ansible_inventory",
    "@@HOME@@": "ansible_home",
    "@@LOCAL_TMP@@": "ansible_local_tmp",
    "@@FACT_CACHE@@": "ansible_fact_cache",
    "@@CONTROL_PATH@@": "ansible_control_path",
    "@@SSH_CONFIG@@": "ansible_ssh_config",
    "@@LOG_PATH@@": "ansible_log",
}


@dataclass(frozen=True, slots=True)
class AnsibleSourceFile:
    path: str
    digest: str


@dataclass(frozen=True, slots=True)
class AnsibleSourceBundle:
    version: str
    files: tuple[AnsibleSourceFile, ...]
    digest: str


def load_ansible_source_bundle() -> AnsibleSourceBundle:
    """Load the exact available package-owned Ansible support files."""

    root = importlib.resources.files("scylla_vms.ansible").joinpath("content")
    actual_paths = set(_resource_paths(root))
    if actual_paths != set(_SOURCE_HASHES):
        raise StatePersistenceError(
            "packaged Ansible source contains missing or unexpected files"
        )
    files: list[AnsibleSourceFile] = []
    aggregate = hashlib.sha256()
    for name, expected_digest in sorted(_SOURCE_HASHES.items()):
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise StatePersistenceError("packaged Ansible source path is invalid")
        resource = root.joinpath(*pure.parts)
        if not resource.is_file():
            raise StatePersistenceError(
                f"packaged Ansible source file is unavailable: {name}"
            )
        data = resource.read_bytes()
        if not data or len(data) > _MAXIMUM_FILE_BYTES or b"\0" in data:
            raise StatePersistenceError("packaged Ansible source content is invalid")
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StatePersistenceError(
                "packaged Ansible source is not UTF-8"
            ) from error
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            raise StatePersistenceError(
                f"packaged Ansible source hash conflicts: {name}"
            )
        files.append(AnsibleSourceFile(name, digest))
        aggregate.update(name.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
    return AnsibleSourceBundle(
        ANSIBLE_SOURCE_VERSION,
        tuple(files),
        "sha256:" + aggregate.hexdigest(),
    )


def _resource_paths(root: Traversable, prefix: str = "") -> tuple[str, ...]:
    paths: list[str] = []
    for entry in root.iterdir():
        if entry.name == "__pycache__":
            continue
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        if entry.is_file():
            paths.append(relative)
        elif entry.is_dir():
            paths.extend(_resource_paths(entry, relative))
    return tuple(sorted(paths))


def packaged_playbook_path(name: str) -> Path:
    """Return a registry-known packaged playbook and validate its file identity."""

    definition = get_playbook(name)
    if not definition.source_available:
        raise StatePersistenceError(
            f"Ansible playbook source is unavailable: {definition.name}"
        )
    filename = definition.filename
    resource = importlib.resources.files("scylla_vms.ansible").joinpath(
        "content", "playbooks", filename
    )
    path = Path(str(resource))
    try:
        info = path.lstat()
    except OSError as error:
        raise StatePersistenceError(
            "packaged Ansible playbook is unavailable"
        ) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise StatePersistenceError("packaged Ansible playbook has an unsafe type")
    return path.resolve(strict=True)


def stage_ansible_config(paths: StatePaths, *, lock: "ClusterLock") -> str:
    """Render the reviewed config with every controller path under cluster state."""

    lock.assert_held_for(paths)
    rendered = _render_ansible_config(paths)
    _atomic_text(paths.ansible_config, rendered)
    return "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def validate_ansible_config(paths: StatePaths) -> str:
    """Require the current owner-only config to equal the anchored rendering."""

    expected = _render_ansible_config(paths)
    validate_state_file(paths.ansible_config)
    try:
        data = paths.ansible_config.read_bytes()
        rendered = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as error:
        raise StatePersistenceError("rendered Ansible config is unreadable") from error
    if len(data) > _MAXIMUM_FILE_BYTES or rendered != expected:
        raise StatePersistenceError("rendered Ansible config conflicts with source")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _render_ansible_config(paths: StatePaths) -> str:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise UnsafePathError("Ansible paths do not match the canonical layout")
    for directory in (
        paths.ansible,
        paths.ansible_home,
        paths.ansible_local_tmp,
        paths.ansible_fact_cache,
        paths.ansible_control_path,
    ):
        validate_state_directory(directory)
    template = (
        importlib.resources.files("scylla_vms.ansible")
        .joinpath("content", "ansible.cfg")
        .read_text(encoding="utf-8")
    )
    rendered = template
    for token, attribute in _CONFIG_TOKEN.items():
        value = Path(getattr(paths, attribute))
        if not value.is_relative_to(paths.cluster_root):
            raise UnsafePathError("Ansible runtime path escapes cluster state")
        rendered = rendered.replace(token, str(value))
    if "@@" in rendered:
        raise StatePersistenceError("Ansible config has an unresolved template token")
    return rendered


def _atomic_text(path: Path, text: str) -> None:
    validate_state_file(path, allow_missing=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    validate_state_file(temporary, allow_missing=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        data = text.encode("utf-8")
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise StatePersistenceError(
                    "atomic Ansible runtime write made no progress"
                )
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        path.chmod(0o600)
    except OSError as error:
        raise StatePersistenceError("atomic Ansible runtime write failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()
