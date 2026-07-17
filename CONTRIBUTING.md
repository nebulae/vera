# Contributing

`main` is protected: no direct pushes, no force-pushes, no branch deletions.
Every change lands through a pull request.

## The flow

```sh
git checkout -b short-topic-name      # branch off main
# ... make changes, commit ...
git push -u origin short-topic-name   # push the branch
gh pr create --fill                   # open the PR
gh pr merge --squash --delete-branch  # merge it (no approval required)
```

Direct `git push origin main` is rejected by branch protection — always go
through a branch and PR.

## Notes

- **Approvals:** none are required, so the repo owner can merge their own PRs.
  Anyone can *open* a PR (it's just a proposal); only accounts with write
  access can merge one.
- **Force-push / delete `main`:** blocked by the rule. The repo owner (admin)
  can override in a pinch, but avoid it — history on `main` should stay linear
  and intact.
- **Before opening a PR:** run the tests.

  ```sh
  pip install -e ".[dev]" && pytest
  ```
