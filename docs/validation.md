# Validation scope

The server/common packages were built during the upstream refactor. Focused tests cover
server routes, authentication requirements, event normalization, rule loading and YARA
metadata. Background jobs and alert emission are disabled in these tests.

The server-only export passed all 9 focused tests before publication on 1 November 2026.
The lab-readiness update subsequently passed 16 tests, including command retrieval and
acknowledgement, cross-system queue filtering, lab-mode response blocking, unavailable
feature reporting, feedback edits and detector sequence ordering. These tests also
exercise an ordinary analysis path that previously failed in Isolation Forest scoring.
Its 86 tracked source/configuration/documentation files were checked for credential
patterns and private runtime artifacts, with no findings. No claim is made that its
ML models are trained, accurate, or ready for production. Windows agent/service checks
are outside this repository. The original development host was Windows; live Linux
deployment still needs verification in your environment.
