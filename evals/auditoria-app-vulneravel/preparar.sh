#!/usr/bin/env bash
# Monta o projeto de teste no workspace vazio do eval.
# Os arquivos que o Claude Code carregaria como configuração (CLAUDE.md, .claude/, .gitignore)
# ficam no repositório com outro nome e só ganham o nome real aqui, dentro do workspace.
set -euo pipefail

ORIGEM="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/projeto"
cp -R "$ORIGEM/." .
mv gitignore.fixture .gitignore
mv CLAUDE.md.fixture CLAUDE.md
mv _claude .claude

git init -q
git add -A
git -c user.name=eval -c user.email=eval@example.invalid commit -q -m "projeto de teste"
