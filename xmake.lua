add_rules("mode.releasedbg")
set_languages("cxx23", "asm")
set_defaultmode("releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

target("example-driver")
    add_rules("wdk.driver", "wdk.env.kmdf")
    set_values("wdk.sign.mode", "test")
    set_values("wdk.sign.digest_algorithm", "sha256")
    add_defines("NOMINMAX")

    add_syslinks("ntoskrnl", "hal", "wmilib")
    add_files("src/**.cc", "src/**.asm")
