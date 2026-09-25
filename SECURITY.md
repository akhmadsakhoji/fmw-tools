# Security policy

FMW Tools opens complete copies of websites, including their databases and credentials, often from sources that cannot be trusted. We treat security reports as the highest priority.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the affected version or commit,
- the steps to reproduce, or a proof of concept (a crafted `.fmw` file is ideal),
- the impact as you understand it.

## What to expect

| Step | Target |
|---|---|
| First response | within 72 hours |
| Assessment and severity | within 7 days |
| Fix for critical issues | as fast as possible, usually within 14 days |

We will keep you informed, credit you in the release notes unless you prefer otherwise, and coordinate the disclosure date with you.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: anything a crafted archive can make FMW Tools do, for example writing outside the extraction folder, following or creating links that escape it, using content that failed its checksum, excessive memory or CPU use, and weaknesses in how encrypted backups are authenticated or decrypted.

Out of scope: the WordPress plugin (report those in its own repository), and attacks that need control of the machine FMW Tools runs on.
