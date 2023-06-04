
### General Notes

> Open source VLSI tool built around open-source tools.
> Collection of scripts that run tools for chip design.
> [Documentation](https://openlane.readthedocs.io/en/latest/)

>[Config File](https://github.com/The-OpenROAD-Project/OpenLane/blob/master/configuration/README.md)
---

### Run a design

> Requires python, venv, and [[Docker]] installed.

``` bash
git clone https://github.com/efabless/openlane.git
cd openlane/
make
make mount

// to run the openlane on one of the designs (xtea)
./flow.tcl -design xtea
```

> This clones openlane, `cd` into the directory and then `make` using the `makefile`.
> We can then run openlane one of the designs called `xtea`.

---

### Info

> These can be found in the run folder of the design.
* `runtime.yaml` for the time taken for each step of running the flow.
* 