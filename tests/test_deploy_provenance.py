"""Deploy provenance: deploy.py refusing a dirty tree and recording where its
bytes came from, and verify_deploy.py checking a deployment against it.

The deploy tests run deploy.main against a throwaway git repository in a
temporary directory, with the key, the RPC and the broadcast stubbed out, so
nothing is signed or sent and the real deployments.json is never written.

The verify tests use tests/fixtures/deploy_registry_v1.json: the stored
deploy transaction of Registry v1 (0x1E1380B7...), recorded read-only from
ConsensusData.getTransactionAllData on Bradbury on 26 September 2026. No
test touches the network.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import rlp

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import chain
import deploy
import provenance
import txstate
import verify_deploy

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TX_ID = "0x88e06a33bfd5c35dabe4ef49bb0cd69a208eed942dca60576bc08bed6e275058"
ADDRESS = "0x1E1380B71F1C9c622C432B6FD6fa56097B1E4Ddc"
REGISTRY_COMMIT = "a56f1c965687614cb15b6ac42cfbb7f7da285a5d"
REGISTRY_SHA256 = "5a122451772568136bbce051910e18e799d00bac3affb75e793a8261a743b7d7"
DKIMKEY_SHA256 = "93e04f5410f5af23286d14723898086303b58572050ab63c40eeac4b5ce50cda"


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---- a throwaway repository -----------------------------------------------

LIBRARY = "def helper():\n    return 1\n"

# The same shape as contracts/*/build.py: module level paths, one of them into
# lacre/, and build() returning the source first.
BUILD = '''from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "demo_template.py"
SOURCE = ROOT / "lacre" / "demo_lib.py"
OUTPUT = HERE / "demo.py"


def build():
    source = TEMPLATE.read_text(encoding="ascii").replace("# @@LIB@@", SOURCE.read_text())
    return source, "", []
'''

TEMPLATE = '# { "Depends": "py-genlayer:test" }\n# @@LIB@@\n'


def git(root, *args):
    # The user's own git configuration, signing included, is kept out of a
    # repository that exists only for the test.
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=test", "-c", "user.email=test@example.com",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"] + list(args),
        check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "contracts" / "demo").mkdir(parents=True)
    (root / "lacre").mkdir()
    (root / "lacre" / "demo_lib.py").write_text(LIBRARY)
    (root / "contracts" / "demo" / "build.py").write_text(BUILD)
    (root / "contracts" / "demo" / "demo_template.py").write_text(TEMPLATE)
    (root / "contracts" / "demo" / "demo.py").write_text(TEMPLATE.replace("# @@LIB@@", LIBRARY))
    (root / "README.md").write_text("demo\n")
    (root / ".gitignore").write_text("ignored/\n")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "demo")
    return root


def head(root):
    return git(root, "rev-parse", "HEAD").strip()


class Client:
    def __init__(self):
        eth = type("Eth", (), {"get_balance": staticmethod(lambda address: 10 ** 18)})
        self.w3 = type("W3", (), {"eth": eth})()

    def wait_for_transaction_receipt(self, transaction_hash, **_):
        return {"status_name": "ACCEPTED", "tx_execution_result_name": "FINISHED_WITH_RETURN",
                "result_name": "AGREE", "tx_data_decoded": {"contract_address": ADDRESS}}


def run_deploy(monkeypatch, root, *flags):
    account = type("Account", (), {"address": "0x" + "ab" * 20})()
    connected = []

    def connect(network):
        connected.append(network)
        return account, Client(), chain.NETWORKS["bradbury"]

    monkeypatch.delenv("PROBE_PK", raising=False)
    monkeypatch.setattr(deploy, "ROOT", root)
    monkeypatch.setattr(deploy, "DEPLOYMENTS", root / "deployments.json")
    monkeypatch.setattr(chain, "connect", connect)
    monkeypatch.setattr(chain, "deploy_calldata", lambda *args: "0x")
    monkeypatch.setattr(chain, "estimate", lambda *args, **kwargs: 1000)
    monkeypatch.setattr(chain, "send", lambda *args, **kwargs: (TX_ID, 1000))
    monkeypatch.setattr(chain, "show_receipt", lambda receipt: None)
    monkeypatch.setattr(sys, "argv",
                        ["deploy.py", str(root / "contracts" / "demo" / "demo.py")] + list(flags))
    deploy.main()
    return connected


def recorded(root):
    return json.loads((root / "deployments.json").read_text())["bradbury"]["demo"]


# ---- the dirty-tree refusal -------------------------------------------------

def test_a_clean_tree_deploys_and_records_its_commit(monkeypatch, capsys, repo):
    assert run_deploy(monkeypatch, repo) == ["bradbury"]
    entry = recorded(repo)
    assert entry["commit"] == head(repo)
    assert entry["commit_dirty"] is False
    out = capsys.readouterr().out
    assert "commit       : %s (clean tree)" % (head(repo),) in out
    assert "dirty        :" not in out


def test_a_modified_tracked_file_anywhere_refuses_before_the_key(monkeypatch, capsys, repo):
    (repo / "README.md").write_text("changed\n")
    with pytest.raises(SystemExit):
        run_deploy(monkeypatch, repo)
    captured = capsys.readouterr()
    assert "dirty        : modified   README.md (M)" in captured.out
    assert "--allow-dirty" in captured.err
    assert not (repo / "deployments.json").exists()


def test_a_staged_change_is_dirty_too(repo):
    (repo / "lacre" / "demo_lib.py").write_text(LIBRARY + "# more\n")
    git(repo, "add", "lacre/demo_lib.py")
    assert provenance.dirty_paths(repo, "contracts/demo/demo.py") == [
        "modified   lacre/demo_lib.py (M)"]


def test_an_untracked_contract_refuses(monkeypatch, capsys, repo):
    (repo / "contracts" / "other").mkdir()
    (repo / "contracts" / "other" / "new.py").write_text("x = 1\n")
    with pytest.raises(SystemExit):
        run_deploy(monkeypatch, repo)
    assert "dirty        : untracked  contracts/other/new.py" in capsys.readouterr().out


def test_an_untracked_file_outside_the_watched_paths_is_not_dirty(repo):
    (repo / "notes.txt").write_text("scratch\n")
    assert provenance.dirty_paths(repo, "contracts/demo/demo.py") == []


def test_a_source_git_does_not_track_is_dirty(repo):
    (repo / "ignored").mkdir()
    (repo / "ignored" / "probe.py").write_text('# { "Depends": "x" }\n')
    assert provenance.dirty_paths(repo, "ignored/probe.py") == [
        "untracked  ignored/probe.py (not in git)"]


def test_a_stale_artifact_refuses(monkeypatch, capsys, repo):
    # Committed, so the tree is clean, but the artifact was not rebuilt: the
    # module hashes would describe a build that is not what gets deployed.
    (repo / "lacre" / "demo_lib.py").write_text(LIBRARY + "# more\n")
    git(repo, "commit", "-q", "-am", "library only")
    with pytest.raises(SystemExit):
        run_deploy(monkeypatch, repo)
    assert "stale      contracts/demo/demo.py" in capsys.readouterr().out


def test_allow_dirty_deploys_and_marks_the_commit_dirty(monkeypatch, capsys, repo):
    (repo / "README.md").write_text("changed\n")
    (repo / "contracts" / "scratch.py").write_text("x = 1\n")
    assert run_deploy(monkeypatch, repo, "--allow-dirty") == ["bradbury"]
    entry = recorded(repo)
    assert entry["commit"] == head(repo)
    assert entry["commit_dirty"] is True
    assert entry["provenance"] == "recorded at deploy by tools/deploy.py with --allow-dirty"
    out = capsys.readouterr().out
    assert "(DIRTY tree)" in out
    assert "dirty        : untracked  contracts/scratch.py" in out


# ---- the recorded fields ----------------------------------------------------

def test_the_entry_records_the_exact_bytes_and_the_inlined_modules(monkeypatch, capsys, repo):
    run_deploy(monkeypatch, repo)
    source = (repo / "contracts" / "demo" / "demo.py").read_bytes()
    entry = recorded(repo)
    assert entry == {
        "address": ADDRESS,
        "commit": head(repo),
        "commit_dirty": False,
        "consensus_tx": TX_ID,
        "deployed_at": entry["deployed_at"],
        "inlined_modules": {"demo_lib.py": sha(LIBRARY.encode())},
        "provenance": "recorded at deploy by tools/deploy.py",
        "source_path": "contracts/demo/demo.py",
        "source_sha256": sha(source),
        "source_size": len(source),
    }
    # The template is not what is sent; the built artifact is.
    assert entry["source_sha256"] != sha(TEMPLATE.encode())
    out = capsys.readouterr().out
    assert "source sha256: %s" % (sha(source),) in out
    assert "source size  : %d bytes" % (len(source),) in out
    assert "inlined      : lacre/demo_lib.py %s" % (sha(LIBRARY.encode()),) in out
    # Printed before the key is read or anything is sent.
    assert out.index("source sha256") < out.index("deployer")


def test_recording_leaves_every_other_entry_as_it_was(monkeypatch, tmp_path):
    before = (ROOT / "deployments.json").read_text()
    path = tmp_path / "deployments.json"
    path.write_text(before)
    monkeypatch.setattr(deploy, "DEPLOYMENTS", path)
    deploy.record_deployment("bradbury", "demo", ADDRESS, TX_ID, {"commit": "c" * 40})
    after = path.read_text()
    old, new = json.loads(before), json.loads(after)
    assert new["bradbury"].pop("demo")["commit"] == "c" * 40
    assert new == old
    # Same style: two space indent, sorted keys, trailing newline.
    assert after == json.dumps(json.loads(after), indent=2, sort_keys=True) + "\n"
    for name in old["bradbury"]:
        block = json.dumps({name: old["bradbury"][name]}, indent=2, sort_keys=True)
        inner = "\n".join("  " + line for line in block.split("\n")[1:-1])
        assert inner in after


# ---- verify_deploy against recorded chain data -----------------------------

def chain_fixture():
    recorded_tx = json.loads((FIXTURES / "deploy_registry_v1.json").read_text(encoding="ascii"))
    return recorded_tx["recipient"], bytes.fromhex(recorded_tx["txCalldata"][2:])


def run_verify(monkeypatch, capsys, tmp_path, entry, calldata=None, root=ROOT, target="registry"):
    recipient, recorded_calldata = chain_fixture()
    deployments = tmp_path / "deployments.json"
    deployments.write_text(json.dumps({"bradbury": {"registry": entry}}, indent=2))

    def no_key(network):
        raise AssertionError("verify_deploy asked for an account")

    monkeypatch.delenv("PROBE_PK", raising=False)
    monkeypatch.setattr(chain, "connect", no_key)
    monkeypatch.setattr(txstate, "connect_readonly",
                        lambda network: (object(), chain.NETWORKS[network]))
    monkeypatch.setattr(verify_deploy, "stored_calldata",
                        lambda client, tx_id: (recipient, calldata or recorded_calldata))
    monkeypatch.setattr(verify_deploy, "DEPLOYMENTS", deployments)
    monkeypatch.setattr(verify_deploy, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["verify_deploy.py", target])
    status = 0
    try:
        verify_deploy.main()
    except SystemExit as exit:
        status = exit.code
    return status, capsys.readouterr().out


def lines(out, status):
    return [line for line in out.splitlines() if line.startswith(status)]


BACKFILLED = {
    "address": ADDRESS,
    "commit": REGISTRY_COMMIT,
    "consensus_tx": TX_ID,
    "deployed_at": "2026-09-23T14:14:11+00:00",
    "inlined_modules": {"dkimkey.py": DKIMKEY_SHA256},
    "provenance": "established after the fact",
    "source_path": "contracts/registry/registry.py",
    "source_sha256": REGISTRY_SHA256,
    "source_size": 11646,
}


def needs_history():
    try:
        provenance.git(ROOT, "cat-file", "-e", REGISTRY_COMMIT + "^{commit}")
    except provenance.GitError:
        pytest.skip("commit %s is not in this checkout" % (REGISTRY_COMMIT[:7],))


def test_the_fixture_is_the_registry_v1_deploy():
    recipient, calldata = chain_fixture()
    assert recipient == ADDRESS
    assert sha(verify_deploy.deployed_code(calldata)) == REGISTRY_SHA256


def test_verify_matches_a_recorded_deploy(monkeypatch, capsys, tmp_path):
    needs_history()
    status, out = run_verify(monkeypatch, capsys, tmp_path, dict(BACKFILLED))
    assert status == 0
    assert [line.split()[1] for line in lines(out, "match")] == [
        "address", "recorded", "recorded", "artifact", "build", "lacre/dkimkey.py"]
    assert not lines(out, "MISMATCH") and not lines(out, "cannot")
    assert "result       : 6 match, 0 mismatch, 0 cannot check" in out


def test_verify_finds_changed_chain_bytes(monkeypatch, capsys, tmp_path):
    needs_history()
    _, calldata = chain_fixture()
    code, constructor, leader_only = rlp.decode(calldata)
    tampered = rlp.encode([code.replace(b"def ", b"def  ", 1), constructor, leader_only])
    status, out = run_verify(monkeypatch, capsys, tmp_path, dict(BACKFILLED), calldata=tampered)
    assert status == 1
    assert [line.split()[1] for line in lines(out, "MISMATCH")] == [
        "recorded", "recorded", "artifact", "build"]
    # The module hashes are about the commit, not the chain, and still hold.
    assert lines(out, "match")[-1].split()[1] == "lacre/dkimkey.py"


def test_verify_finds_a_wrong_recorded_hash(monkeypatch, capsys, tmp_path):
    needs_history()
    entry = dict(BACKFILLED, source_sha256="0" * 64,
                 inlined_modules={"dkimkey.py": "1" * 64})
    status, out = run_verify(monkeypatch, capsys, tmp_path, entry)
    assert status == 1
    assert [line.split()[1] for line in lines(out, "MISMATCH")] == [
        "recorded", "lacre/dkimkey.py"]


def current_tree(tmp_path):
    """A working tree whose registry.py is the deployed source, no build."""
    root = tmp_path / "tree"
    (root / "contracts" / "registry").mkdir(parents=True)
    _, calldata = chain_fixture()
    (root / "contracts" / "registry" / "registry.py").write_bytes(
        verify_deploy.deployed_code(calldata))
    return root


def test_verify_an_entry_with_no_commit_says_what_it_cannot_check(monkeypatch, capsys,
                                                                  tmp_path):
    entry = {"address": ADDRESS, "consensus_tx": TX_ID,
             "deployed_at": "2026-09-23T14:14:11+00:00"}
    status, out = run_verify(monkeypatch, capsys, tmp_path, entry, root=current_tree(tmp_path))
    assert status == 0
    assert [line[14:].split("  ")[0] for line in lines(out, "cannot check")] == [
        "recorded hash", "recorded size", "commit"]
    assert "no commit recorded for this entry" in out
    [current] = [line for line in lines(out, "match") if "current build" in line]
    assert "contracts/registry/registry.py (assumed from the name)" in current


def test_verify_an_unknown_commit_still_compares_the_current_build(monkeypatch, capsys,
                                                                   tmp_path):
    root = current_tree(tmp_path)
    (root / "contracts" / "registry" / "registry.py").write_text("# something else\n")
    entry = {"address": ADDRESS, "commit": None, "consensus_tx": TX_ID,
             "provenance": "commit unknown", "source_sha256": REGISTRY_SHA256}
    status, out = run_verify(monkeypatch, capsys, tmp_path, entry, root=root)
    assert status == 1
    assert "the commit is recorded as unknown: commit unknown" in out
    assert [line.split()[1] for line in lines(out, "MISMATCH")] == ["current"]


def test_verify_takes_an_address(monkeypatch, capsys, tmp_path):
    needs_history()
    status, out = run_verify(monkeypatch, capsys, tmp_path, dict(BACKFILLED),
                             target=ADDRESS.lower())
    assert status == 0
    assert "contract     : registry %s" % (ADDRESS,) in out
