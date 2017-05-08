README.md

A small tool to pass a YAML file that contains system-wide registries for docker,
runc, and friends. BY default, the tooling will look at the YAML file in
`/etc/containers/registries.conf`.


To compile:

```
sudo make install
```

See docs/ for explicit instructions on how to run.
