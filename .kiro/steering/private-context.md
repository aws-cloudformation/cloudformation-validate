# Confidential Agent Context and Skills

Before starting any task in this repository:

1. If `.kiro/private/` exists, recursively discover and read every readable regular file in it before planning or
   making changes. Do not follow symlinks that resolve outside `.kiro/private/`.
2. Use applicable content as supplemental agent context, and follow any task-relevant skill instructions found there.
   Resolve conflicts according to the normal instruction priority.
3. Treat both filenames and contents as confidential. Do not quote, summarize, or copy them into tracked files, logs,
   commit messages, review descriptions, or responses unless the user explicitly asks for that specific disclosure.
4. `.kiro/private/` and its contents must remain untracked and must never be added to version control.
5. If the directory is absent or empty, continue normally without treating it as an error.
