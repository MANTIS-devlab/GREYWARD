# Simple desktop test: Application Guard and Protected Data

## Terminal fixtures added on 9 October 2026

The user explicitly requested terminal testing in addition to the earlier
mouse-only scenarios below. The normal enrolled `development-user` account on `.149`
now has two harmless scripts in `~/GREYWARD-Guard-Tests/`:
`legitimate-read.sh` and `threat-read.sh`. Each only prints a description,
attempts to read `/home/development-user/.ssh/greyward_mock_key.txt`, and returns the
read exit status. The file contains synthetic text, not a usable SSH key.
It has mode 0600, is owned by `development-user`, and has the existing registered SSH
directory resource label. Existing credentials and grants were not changed.

Live checks through the normal enrolled SSH account:

- Both scripts return permission denied and exit 1 before any grant.
- `/usr/bin/sudo -n /usr/bin/cat -- /home/development-user/.ssh/greyward_mock_key.txt`
  is denied at sudo execution. No fresh interactive sudo authentication was
  tested. Do not promise that an authenticated sudo command is currently usable.
- `greyward-guard grant review /home/development-user/GREYWARD-Guard-Tests/legitimate-read.sh
  resource_d8be0f8653b46e904ffdc90ee5bab65f6da49a47470edb30f274d420d07e0d99`
  returns provider unavailable without fallback. The implemented reviewed-tool
  profile is fixed SSH key inspection; arbitrary script/cat raw-read grants and
  their temporary-grant fallback are unavailable. This is an undelivered
  legitimate-access scenario, not a passing allow/revoke acceptance test.

The scripts have the same access attempt deliberately: intent or filename
cannot authorize access. Only an implemented reviewed identity/domain/grant
workflow could distinguish an approved workload. Do not grant the generic
shell, interpreter, or cat executable broad credential access to make this pass.

The following guide remains the earlier desktop-only acceptance procedure.

For the enrolled `development-user` desktop on `.149`. Use the mouse and Security
Center. **Do not open Terminal.** The prepared launchers are in the application
menu, and the test key is synthetic. Never save, copy, or use it to connect to
anything.

## 1. Check normal use

1. Open **Guard Acceptance — Edit Everyday Note** from the application menu.
2. Type a few words, save, close it, then open it again.

**Pass:** the note is still there and no Security Center permission prompt
appeared. The note is harmless and can stay on the VM.

## 2. Review sensitive access

1. Open **Security Center → Protected Data**.
2. Open **Custom protected directory → Review tool access**.
3. In the chooser, select **ssh-keygen**. Read the review. Continue only if it
   says **SSH key inspection only**, names the protected directory, and says
   key contents/output are withheld. Approve only that exact review using the
   normal authentication window.
4. Confirm the grant appears in Security Center. Then select **Revoke access**,
   confirm the same application and directory, and wait for the grant to
   disappear.

**Pass:** Security Center shows the specific grant completed and verified, then
shows it revoked. No key contents are displayed.

**Limit:** the current Security Center has no button to run an approved app
with that grant. This step tests the real permission review and kernel readback,
but cannot prove an allowed app read. Do not use Terminal to work around this.

## 3. Check automatic blocking

1. Open **Guard Acceptance — Try Protected Test File** from the application
   menu. It opens the real Text Editor on the protected synthetic test file.
2. Do not approve any access prompt. Close the editor without saving.
3. In **Security Center → Activity**, look for the matching access denial.

**Pass:** the file contents are not shown, no authorization offer appears, and
Activity identifies a kernel denial. If Activity cannot confirm a kernel
denial, record this step as **not confirmed**, not passed.

## Before you start

In **Security Center → Protected Data**, the directory should say **Protected**.
If it does not, stop and tell me. The current guest was prepared with this
protection active. The test changes no protection settings.

## Reset

After step 2, revoke the grant as instructed. Close the editor after each step.
Leave the denial in Activity so it can be reviewed. Nothing else needs to be
reset.

The existing `greyward-live-ui-review.service` and WebKitWebDriver were already
running during preparation. If another person or review is actively using the
desktop, wait until it is finished before starting your test.
