# Confidential Agent Context and Skills

Before starting any task in this repository:

1. If `.kiro/steering/private/` exists, use a direct filesystem directory read that does not apply `.gitignore` to
   recursively enumerate it before planning or making changes. Do not rely on a gitignore-aware glob or search as the
   sole discovery mechanism. Read every readable regular file that is not already present in context.
2. Do not follow symlinks that resolve outside `.kiro/steering/private/`.
3. Use applicable content as supplemental agent context, and follow any task-relevant skill instructions found there.
   Resolve conflicts according to the normal instruction priority.
4. Treat both filenames and contents as confidential. Do not quote, summarize, or copy them into tracked files, logs,
   commit messages, review descriptions, or responses unless the user explicitly asks for that specific disclosure.
5. `.kiro/steering/private/` and its contents must remain untracked and must never be added to version control.
6. If the directory is absent or empty, continue normally without treating it as an error.
