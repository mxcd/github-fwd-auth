set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# start the Go API with live reload
air:
  air -c .air.toml

count:
  cloc . --exclude-dir=node_modules,ent,sandbox --fullpath --not-match-d=^\.\/ent\/schema

# pushes all changes to the main branch
push +COMMIT_MESSAGE:
  git add .
  git commit -m "{{COMMIT_MESSAGE}}"
  git pull origin main
  git push origin main

tag TAG_VERSION:
  git tag {{TAG_VERSION}}
  git push origin {{TAG_VERSION}}
  git tag pkg/githuboauth/{{TAG_VERSION}}
  git push origin pkg/githuboauth/{{TAG_VERSION}}