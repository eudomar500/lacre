"""Which commit and which bytes a deployment came from.

Shared by deploy.py, which records these facts when it deploys, and
verify_deploy.py, which checks them against the chain afterwards. Nothing
here reads a key or talks to the network; everything comes from git and from
the files on disk.

A contract is deployed as source, so the deployed bytes are the artifact the
build wrote, not the template. The build beside an artifact (build.py in the
same directory, writing that file as its OUTPUT) is imported and asked for
its output, which is how the lacre/ modules it inlined are found: they are
the module level paths of the build that point into lacre/. A contract with
no build beside it is its own source and inlines nothing.
"""

import contextlib
import hashlib
import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# Untracked files here change what a build produces, so they make a tree
# dirty even though git status alone would let a commit ignore them.
WATCHED = ("contracts", "lacre")

RECORDED_AT_DEPLOY = "recorded at deploy by tools/deploy.py"


class GitError(Exception):
    pass


def git(root, *args, binary=False):
    result = subprocess.run(["git", "-C", str(root)] + list(args), capture_output=True)
    if result.returncode != 0:
        raise GitError(result.stderr.decode("utf-8", "replace").strip()
                       or "git %s failed" % (args[0],))
    return result.stdout if binary else result.stdout.decode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def relative(root, path):
    """path as git names it inside root, or None when it is outside root."""
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return None


def head_commit(root):
    return git(root, "rev-parse", "HEAD").strip()


def _inside(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def dirty_paths(root, source):
    """Why HEAD does not account for the tree a deploy of source runs from.

    Every uncommitted change to a tracked file counts, staged or not, since
    the recorded commit is a claim about the whole tree. Untracked files count
    under contracts/, lacre/ and the source path, where they can change what
    is built. A source that git does not track, because it is new, ignored or
    outside the repository, counts too: no commit contains it.
    """
    problems = []
    if source is None:
        return ["outside    the source is not inside the repository"]
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                 binary=True).split(b"\0")
    index = 0
    while index < len(status):
        entry = status[index].decode("utf-8", "replace")
        index += 1
        if not entry:
            continue
        code, path = entry[:2], entry[3:]
        if code[0] in "RC":
            # -z puts a rename's original path in the next field.
            index += 1
        if code == "??":
            if any(_inside(path, watched) for watched in WATCHED + (source,)):
                problems.append("untracked  %s" % (path,))
        elif code != "!!":
            problems.append("modified   %s (%s)" % (path, code.strip()))
    try:
        git(root, "ls-files", "--error-unmatch", "--", source)
    except GitError:
        if not any(problem.endswith(" " + source) for problem in problems):
            problems.append("untracked  %s (not in git)" % (source,))
    return problems


def _load(path):
    """The module at path, imported under a name nothing else uses.

    No bytecode is written, so importing a build leaves no file behind in the
    tree it was imported from.
    """
    name = "lacre_build_%s" % (sha256(str(path).encode())[:16],)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def build_of(root, source):
    """(what the build beside source produces, the lacre modules it inlines).

    (None, {}) when source has no build: nothing to rebuild and nothing
    inlined. The build is only trusted to be this artifact's own when its
    OUTPUT is source.
    """
    root = Path(root)
    artifact = root / source
    build = artifact.parent / "build.py"
    if not build.is_file():
        return None, {}
    module = _load(build)
    output = getattr(module, "OUTPUT", None)
    if output is None or Path(output).resolve() != artifact.resolve():
        return None, {}
    library = (root / "lacre").resolve()
    modules = {}
    for value in vars(module).values():
        if isinstance(value, Path) and value.suffix == ".py":
            value = value.resolve()
            if value.parent == library and value.is_file():
                modules[value.name] = sha256(value.read_bytes())
    built = module.build()
    if isinstance(built, tuple):
        built = built[0]
    return built.encode("ascii"), dict(sorted(modules.items()))


@contextlib.contextmanager
def tree_at(root, commit):
    """A temporary directory holding the tracked files of commit."""
    archive = git(root, "archive", "--format=tar", commit, binary=True)
    with tempfile.TemporaryDirectory(prefix="lacre-%s-" % (commit[:7],)) as directory:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(directory, filter="data")
        yield Path(directory)


def collect(root, path, source, allow_dirty):
    """The provenance fields of a deploy of source, the bytes read from path.

    Returns (fields, problems). problems is empty for a deploy HEAD fully
    accounts for. It also lists an artifact that is not what its build
    produces now: then the inlined module hashes would describe a build that
    was never deployed. Any problem marks the commit dirty.
    """
    root = Path(root)
    source_path = relative(root, path)
    try:
        commit = head_commit(root)
        problems = dirty_paths(root, source_path)
    except GitError as error:
        commit = None
        problems = ["git        %s" % (error,)]

    built, modules = build_of(root, source_path) if source_path else (None, {})
    if built is not None and built != source:
        problems.append("stale      %s is not what its build.py produces now; rebuild it"
                        % (source_path,))

    fields = {
        "commit": commit,
        "commit_dirty": bool(problems),
        "inlined_modules": modules,
        "provenance": RECORDED_AT_DEPLOY + (" with --allow-dirty" if allow_dirty and problems
                                            else ""),
        "source_path": source_path or str(path),
        "source_sha256": sha256(source),
        "source_size": len(source),
    }
    return fields, problems


def show(fields):
    """The provenance lines of a deploy log, one fact per line."""
    state = "DIRTY" if fields["commit_dirty"] else "clean"
    print("commit       : %s (%s tree)" % (fields["commit"] or "unknown", state))
    print("source path  : %s" % (fields["source_path"],))
    print("source sha256: %s" % (fields["source_sha256"],))
    print("source size  : %d bytes" % (fields["source_size"],))
    if not fields["inlined_modules"]:
        print("inlined      : nothing from lacre/")
    for name, digest in fields["inlined_modules"].items():
        print("inlined      : lacre/%s %s" % (name, digest))
