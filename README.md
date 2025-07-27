# DLL inject plugin for SystemInformer (process hacker)

Adds back the context menu entry in the process list to load a DLL (same as properties->Modules->Load module)  
I also included an extra manual mapping alternative but i havent tested it much other than simple hello-world.dll, you can disable this menu in the settings if you want.
<img width="657" height="440" alt="image" src="https://github.com/user-attachments/assets/2d7151dd-c17f-4033-9886-969271993c91" />


<img width="582" height="586" alt="SystemInformer_VdpOyXFTr7" src="https://github.com/user-attachments/assets/ce7f73a7-1a3a-47f7-98ec-395e71df10e0" />


## To build

Personally i use xmake since i prefer it over other build systems but ive also included a basic vcxproj 

Building using xmake is just 
[xmake quickstart/installation](https://xmake.io/guide/quick-start.html)


```
xmake -b
```

If you want it to automatically copy itself over to the plugins directory just comment this part of [xmake.lua](xmake.lua)

```lua
-- after_build(function (target)
--     os.cp(target:targetfile(), "C:/Program Files/SystemInformer/plugins/")
-- end)
```

Make sure you also configure the include and lib dirs, we could set xmake to do this but i cba
```lua
add_includedirs("S:/gits/systeminformer/sdk/include")
add_linkdirs("S:/gits/systeminformer/sdk/lib/amd64")
```

You can clone the systeminformer repository to get the SDK files:
```bash
git clone https://github.com/winsiderss/systeminformer
```