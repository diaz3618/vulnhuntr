# Git Workflow

## Critical Rules

1. **Feature branches preferred** - Always work on feature branches
2. **NEVER push to main by default** - Only when explicitly requested
3. **NEVER merge to main by default** - Only when explicitly requested
4. **NEVER use `--force`** without explicit approval
5. **ALWAYS create new commits** - never amend or rebase unless explicitly asked

**By default:**
- Work on feature branches
- Commit and push to feature branches freely
- Do NOT push or merge to main

**ONLY push/merge to main when explicitly requested** with phrases like:
- "merge this into main"
- "push to main"
- "merge with main branch"

**No pull requests needed** - this is a personal repository.

## Commit Policy

**"Explicitly asked"** = user says "amend", "squash", "rebase", or "fix up the commit".

"Looks good" or "go ahead" is NOT permission to rewrite history.

## Standard Workflow

### 1. Create Feature Branch

```bash
git checkout main
git pull origin main
git checkout -b feature/your-branch-name
```

### 2. Make Changes and Commit

```bash
git add <specific-files>    # NEVER blindly add everything
git commit -m "type(scope): description"
```

Commit message format: `type(scope): description` (lowercase, imperative mood)

### 3. Lint and Format

```bash
ruff check --fix .     # Lint and auto-fix
ruff format .          # Format code
```

Fix any remaining errors before proceeding.

**If tests exist**:
```bash
pytest tests/ -v       # Run test suite
```

### 4. Sync with Main

```bash
git fetch origin main
git merge origin/main
```

Resolve any conflicts before pushing.

### 5. Push Feature Branch

```bash
git push -u origin feature/your-branch-name
```

**Stop here by default.** Do NOT merge to main unless explicitly requested.

### 6. Merge to Main (ONLY if explicitly requested)

```bash
# ONLY run these commands if user explicitly asks to merge/push to main
git checkout main
git pull origin main
git merge feature/your-branch-name
git push origin main
```

## Key Points

- **Never blindly `git add .`** - there may be unrelated files
- **Always sync with main** before creating PR to avoid conflicts
- **Don't edit CHANGELOG.md** - it's auto-generated
