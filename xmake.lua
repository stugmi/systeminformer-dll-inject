add_rules("mode.debug", "mode.release")

set_languages("c++20")
target("DllInject")
    set_kind("shared")
    set_targetdir("build")
    add_files("src/*.cpp")
    add_headerfiles("src/*.h")

    add_includedirs("S:/gits/systeminformer/sdk/include")
    add_linkdirs("S:/gits/systeminformer/sdk/lib/amd64")

    add_syslinks("user32", "Advapi32")
    
    -- Enable Control Flow Guard
    add_cxflags("/guard:cf", {force = true})
    add_ldflags("/guard:cf", {force = true})
    
    add_ldflags(
        "/DELAYLOAD:user32.dll",
        "/DELAYLOAD:Advapi32.dll",
        {force = true}
    )

    -- after_build(function (target)
    --     os.cp(target:targetfile(), "C:/Program Files/SystemInformer/plugins/")
    -- end)
