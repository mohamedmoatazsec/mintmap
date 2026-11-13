# Security policy

## Reporting a vulnerability in MintMap

Please report it privately through GitHub:
**[Report a vulnerability](https://github.com/mohamedmoatazsec/mintmap/security/advisories/new)**
(the repository's *Security* tab, then *Report a vulnerability*). Do not open a public issue for it.
If the *Report a vulnerability* button is missing, open an issue titled "Security contact request" with no
details, and the maintainer will reply with a private channel.

Include the MintMap version (`mintmap --version`; 0.6.0a1 has no `--version`, so give `pip show mintmap` or the
commit), what an attacker can do, and the smallest input or pull request that shows it.

MintMap is maintained by one person in their spare time. You will get an answer as soon as that allows; there is
no guaranteed response time. Fixes are made on `main` and released as a new version. Only the latest release is
supported.

## What counts as a vulnerability

MintMap is a CI check, so the interesting attacks are those that let a pull request get past it or abuse the job
it runs in:

- content of the analysed repository (source files, `mintmap.lock`, file names) that makes MintMap **execute
  code**, read or write files outside the project directory, or crash in a way that exits 0;
- a pull request that **replaces or disables the check** while using the action as documented, for example by
  shadowing a module that MintMap imports;
- injection into the job summary or the workflow commands the action writes;
- a problem in `action.yml` or the release workflow that exposes tokens or lets untrusted code run.

## What does not

- **A login or credential path that MintMap misses, a false alarm, or a harmful change that passes `diff`.**
  These are accuracy limits. They are measured and published in [docs/EVALUATION.md](docs/EVALUATION.md), and
  MintMap states that it is a review aid, not a guarantee. Please report them as ordinary issues with the "Missed
  path or false alarm" template: they are welcome.
- A pull request that accepts its own change in `mintmap.lock` when the repository has no code-owner review for
  the lock. That is a configuration matter: see [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).
- Vulnerabilities in a project you scanned with MintMap. Report those to that project.
