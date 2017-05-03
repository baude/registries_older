README.md

To compile:

```
gcc -Wall -g -o registries2 -I/usr/include/json-glib-1.0 -I/usr/include -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -L/usr/lib64/ -lyaml -lglib-2.0 -ljson-glib-1.0 -lgio-2.0 -lgobject-2.0 registries2.c 

```

Try running:

./registries

and then:

./registries -j


