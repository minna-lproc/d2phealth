# D2P Community Health Survey — PythonAnywhere edition

A complete Flask + SQLite application for administrator-managed enumerators, English/Bisaya questionnaires, offline fieldwork, and online result syncing. No ChatGPT account or external database subscription is required.

## Deploy on PythonAnywhere

1. Upload `community-health-pythonanywhere.zip` into your PythonAnywhere home folder using the **Files** tab.
2. Open a **Bash console** and run:

   ```bash
   unzip community-health-pythonanywhere.zip
   cd ~/community-health
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   python manage.py init-admin
   ```

   Choose your own administrator username, display name, and password. Passwords are entered at a hidden prompt. There is no default or packaged password. If Python 3.11 is unavailable, use an available Python 3.10+ version and select the same version in the next step.

3. In the **Web** tab choose **Add a new web app → Manual configuration → Python 3.11** (or the matching version).
4. Set the **Virtualenv** path to:

   ```text
   /home/YOUR_USERNAME/community-health/.venv
   ```

5. Open the WSGI configuration file linked in the Web tab. Replace its example content with this, substituting your actual username:

   ```python
   import sys
   project_path = '/home/YOUR_USERNAME/community-health'
   if project_path not in sys.path:
       sys.path.insert(0, project_path)
   from app import app as application
   ```

   A copy is included as `wsgi.py`. Do not use Flask's development server for PythonAnywhere hosting.

6. Enable **Force HTTPS** in the Web tab and press **Reload**. Open `https://YOUR_USERNAME.pythonanywhere.com`.
7. Log in with the administrator account created in step 2. Open **Team & results** to add enumerators.

All browser assets are served by Flask, including `/sw.js`. **Do not add a static mapping for `/` or `/instance`.** No additional static-file mappings are needed. Keep the application at the root of its domain rather than a subdirectory.

## Enumerator workflow

1. The administrator adds a full name, username, and temporary password under **Team & results**.
2. Give the app URL, username, and temporary password to that person securely. The app does not send emails.
3. On their own phone, the enumerator logs in while online and chooses a new password.
4. Wait for **Offline ready**. Optionally add the app to the Home Screen using the browser menu.
5. Create an interview, select English or Bisaya, and choose any needed disease modules. The enumerator name is assigned from the logged-in account.
6. Every answer is saved on that device. Offline work can continue for up to seven days after the last successful online account verification. First login and password changes require internet.
7. Reopen or keep the app open when internet returns. It verifies account access, uploads pending changes, and downloads that enumerator's synced interviews. **Sync now** provides a manual check. Wait for **All interviews synced** before clearing browser data or changing devices.
8. Administrators see all uploaded results, filter by enumerator, view responses, and export team CSV or JSON files. Enumerators can only retrieve their own records.

Automatic sync runs while the app is open, when the browser reports a reconnection, when the app becomes visible, and periodically while connected. Mobile browsers may suspend closed/background apps; reopening the app resumes sync. Unsynced work cannot be recovered from the server until it has uploaded.

## Conflicts and retries

Each synced interview has a server version. Retrying a successful upload does not duplicate the interview. If two devices change the same interview, the app keeps the local answers and offers a conflict review with both versions. Download a local backup before choosing **Use cloud answers**, or explicitly choose **Keep my local answers & upload** to replace the cloud version.

Survey codes are unique within the current local record list; the underlying interview UUID is the sync identity. Use enumerator-specific prefixes if your study needs globally unique human-readable survey codes.

## Existing records from the earlier app

Browser storage is separate for each domain. Before moving from the original Sites app, download its **JSON Backup**. Log into the new PythonAnywhere app and use **Import** under the account that should own those interviews, then sync. The original device-only backups have no account owner and can be adopted by the importing account. Account-owned backups can only be imported by that same account.

The administrator also sees an **Import older interviews** button if original, unowned device-only records exist on the same domain. Originals are retained until you explicitly clear browser data.

## Accounts and passwords

- Passwords are stored as salted PBKDF2 hashes; the database does not store plaintext passwords.
- Temporary passwords must be changed at first login.
- Administrators can reset enumerator passwords or disable/enable access.
- Password resets and disabling invalidate existing online sessions. Already downloaded offline drafts remain on the enumerator's device; there is no remote wipe.
- For administrator password recovery, activate the virtual environment and run:

  ```bash
  cd ~/community-health
  source .venv/bin/activate
  python manage.py reset-admin
  ```

## Database and backups

The application creates these files on first use:

```text
instance/survey.sqlite3    Accounts, interview results, audit events and login attempts
instance/secret_key        Persistent session-signing key
```

Keep `instance/` when uploading future application updates. It is intentionally absent from this ZIP. The secret key is generated automatically with restricted permissions; you may instead provide a long random `D2P_SECRET_KEY` environment variable. Do not change it during routine reloads.

To make a consistent database backup (including SQLite WAL writes):

```bash
cd ~/community-health
source .venv/bin/activate
python backup.py
```

Download the generated file from `instance/backups/` and keep it securely. Backups include account password hashes and confidential survey responses. Team CSV/JSON exports contain responses, not login passwords. Reinstalling the app with a new empty database creates new account IDs; restore the database backup to preserve account ownership.

SQLite is suitable for a modest field team on one PythonAnywhere application. The app uses write transactions, WAL mode, and a busy timeout to coordinate concurrent uploads. If the study grows substantially, migrate the database before scaling to multiple hosts.

## Local development and tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py init-admin
D2P_DEV_HTTP=1 flask --app app run
```

`D2P_DEV_HTTP=1` allows session cookies over HTTP for localhost development only. Leave it unset on PythonAnywhere. Service workers work on HTTPS or localhost.

Run the server checks with:

```bash
python -m unittest discover -s tests -v
```

Checks cover login, first-login password changes, account restrictions, disabling, resets, CSRF, retry-safe syncing, stale-version conflicts, answer validation, private file protection, and login throttling. Scripted DOM checks during preparation also exercised all 19 sections in both languages, local account separation, the offline queue, and conflict handling. A real phone and airplane-mode test remains necessary after deployment.

## Field pilot before collection

1. Create two test enumerators; confirm each can see only their own interviews.
2. On a phone, sign in, wait for Offline ready, enable airplane mode, enter answers, and reopen the app.
3. Reconnect, keep the app open, press Sync now, and confirm the interview appears in the administrator's results.
4. Sign into the same enumerator account on another device and confirm its interview downloads.
5. Test one conflicting edit across two devices before starting actual data collection.

The 456 questionnaire items are based on the two supplied working documents dated 7 November 2026. They retain the supplied English and Bisaya wording, including Konsulta/YAKAP differences. Questionnaire validation remains in progress, and the app does not calculate research scores.
